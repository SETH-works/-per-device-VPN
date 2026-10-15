#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [Parameter(Mandatory=$true)][ValidateSet('Status','Verify','Arm','VPNBOOK','DIRECT','EmergencyDirect')][string]$Mode,
  [switch]$PlanOnly,
  [switch]$ConfirmDirect,
  [string]$EmergencyPhrase,
  [string]$ConfigPath = "$PSScriptRoot\pilot-client.json"
)
$ErrorActionPreference = 'Stop'
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$stateDir = Join-Path $env:ProgramData 'Walnuts'
$statePath = Join-Path $stateDir 'pc-stream-pilot.json'
$group = 'Project Walnuts PC-STREAM pilot'
$rulePrefix = 'Walnuts Pilot '

function Assert-Target([bool]$NeedTailscale = $true, [bool]$NeedPilotBaseline = $true) {
  if ($env:COMPUTERNAME -ne $config.ClientHostname) { throw "Wrong PC: expected $($config.ClientHostname), got $env:COMPUTERNAME" }
  $adapter = Get-NetAdapter -Name $config.EthernetAlias -ErrorAction Stop
  if ($NeedPilotBaseline) {
    if ($adapter.Status -ne 'Up') { throw "Ethernet adapter $($config.EthernetAlias) is not Up" }
    if ((Get-NetIPInterface -InterfaceAlias $config.EthernetAlias -AddressFamily IPv4).Dhcp -ne 'Enabled') { throw 'Ethernet IPv4 is not DHCP-managed; refusing pilot setup' }
    $ipcfg = Get-NetIPConfiguration -InterfaceAlias $config.EthernetAlias
    $lan = @($ipcfg.IPv4Address | ForEach-Object IPAddress)
    if ($lan -notcontains $config.LanIPv4 -or $ipcfg.IPv4DefaultGateway.NextHop -ne $config.GatewayIPv4) { throw 'PC-STREAM Ethernet address or gateway differs from the reviewed baseline' }
  }
  $ts = @(Get-NetAdapter | Where-Object { $_.InterfaceDescription -match 'Tailscale' -and $_.Status -eq 'Up' })
  if ($ts.Count -ne 1) {
    if ($NeedTailscale) { throw "Expected exactly one Up Tailscale adapter; found $($ts.Count)" }
    return $null
  }
  return $ts[0]
}
function Get-TailscaleExe {
  $svc = Get-CimInstance Win32_Service -Filter "Name='Tailscale'"
  if (-not $svc) { throw 'Tailscale Windows service is not installed' }
  $path = [regex]::Match($svc.PathName, '^"?(.+?\.exe)').Groups[1].Value
  $candidate = Join-Path (Split-Path $path) 'tailscale.exe'
  if (-not (Test-Path -LiteralPath $candidate)) { throw "Could not resolve trusted tailscale.exe beside $path" }
  return $candidate
}
function Get-Prefs($exe) {
  $raw = & $exe debug prefs 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'tailscale debug prefs failed' }
  return ($raw | ConvertFrom-Json)
}
function Save-Baseline($adapter, $exe, [bool]$AllowExitNode = $false) {
  if (Test-Path $statePath) { return (Get-Content -Raw $statePath | ConvertFrom-Json) }
  $profiles = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultOutboundAction
  $prefs = Get-Prefs $exe
  if (($prefs.ExitNodeIP -or $prefs.ExitNodeID) -and -not $AllowExitNode) { throw 'PC-STREAM already has a Tailscale exit node selected; review it and use explicit EmergencyDirect only if intended.' }
  $ethernetDns4 = Get-DnsClientServerAddress -InterfaceAlias $config.EthernetAlias -AddressFamily IPv4
  $tailscaleDns4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4
  $tailscaleDns6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6
  $baseline = [ordered]@{
    Version=2; Hostname=$env:COMPUTERNAME; EthernetAlias=$config.EthernetAlias
    TailscaleAlias=$adapter.Name; TailscaleIfIndex=$adapter.ifIndex; TailscaleExe=$exe; OriginalProfiles=@($profiles)
    OriginalEthernetDnsIPv4=@($ethernetDns4.ServerAddresses)
    OriginalTailscaleDnsIPv4=@($tailscaleDns4.ServerAddresses); OriginalTailscaleDnsIPv6=@($tailscaleDns6.ServerAddresses); OriginalDhcp='Enabled'
    OriginalAcceptDNS=[bool]$prefs.CorpDNS; OriginalExitNodeIP=$prefs.ExitNodeIP; OriginalExitNodeID=$prefs.ExitNodeID
    CapturedUtc=[DateTime]::UtcNow.ToString('o')
    Mode='DIRECT'; ClientIPv4=$config.ClientTailscaleIPv4; ClientIPv6=$config.ClientTailscaleIPv6
  }
  if ($PlanOnly) { return [pscustomobject]$baseline }
  New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true,$false)
  foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($sid)), 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $stateDir -AclObject $acl
  $baseline | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath $statePath
  return [pscustomobject]$baseline
}
function Invoke-Tailscale($state, [string[]]$Args) {
  if ($PlanOnly) { Write-Output ("PLAN: {0} {1}" -f $state.TailscaleExe, ($Args -join ' ')); return }
  & $state.TailscaleExe @Args
  if ($LASTEXITCODE -ne 0) { throw "Tailscale command failed: $($Args -join ' ')" }
}
function Add-LockdownRules($state) {
  if ($PlanOnly) { Write-Output 'PLAN: add outbound allows for Tailscale adapter, Tailscale daemon, and Ethernet DHCP; block IPv6; set all profile outbound defaults to Block'; return }
  $exists = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
  $names = @($exists | ForEach-Object DisplayName)
  if (($names -notcontains ($rulePrefix+'Tailscale interface'))) { New-NetFirewallRule -DisplayName ($rulePrefix+'Tailscale interface') -Group $group -Direction Outbound -Action Allow -Profile Any -InterfaceAlias $state.TailscaleAlias | Out-Null }
  if (($names -notcontains ($rulePrefix+'Tailscale transport'))) { New-NetFirewallRule -DisplayName ($rulePrefix+'Tailscale transport') -Group $group -Direction Outbound -Action Allow -Profile Any -Program $state.TailscaleExe | Out-Null }
  if (($names -notcontains ($rulePrefix+'DHCP renew'))) { New-NetFirewallRule -DisplayName ($rulePrefix+'DHCP renew') -Group $group -Direction Outbound -Action Allow -Profile Any -InterfaceAlias $state.EthernetAlias -Program "$env:SystemRoot\System32\svchost.exe" -Service Dhcp -Protocol UDP -LocalPort 68 -RemotePort 67 | Out-Null }
  if (($names -notcontains ($rulePrefix+'Block IPv6 egress'))) { New-NetFirewallRule -DisplayName ($rulePrefix+'Block IPv6 egress') -Group $group -Direction Outbound -Action Block -Profile Any -Protocol IPv6 | Out-Null }
  Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled True -DefaultOutboundAction Block
}
function Test-RuleShape($rule, [string]$Action, [string]$Direction) {
  return ($null -ne $rule -and $rule.Enabled -eq 'True' -and $rule.Action -eq $Action -and
          $rule.Direction -eq $Direction -and $rule.Profile -eq 'Any')
}
function Get-LockdownAssessment($state, $adapter, $prefs) {
  $issues = [System.Collections.Generic.List[string]]::new()
  $profiles = @(Get-NetFirewallProfile)
  if (@($profiles | Where-Object { $_.Enabled -ne $true -or $_.DefaultOutboundAction -ne 'Block' }).Count) { $issues.Add('firewall_profiles_not_enabled_and_outbound_block') }
  $rules = @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue)
  $iface = $rules | Where-Object DisplayName -eq ($rulePrefix+'Tailscale interface') | Select-Object -First 1
  $transport = $rules | Where-Object DisplayName -eq ($rulePrefix+'Tailscale transport') | Select-Object -First 1
  $dhcp = $rules | Where-Object DisplayName -eq ($rulePrefix+'DHCP renew') | Select-Object -First 1
  $ipv6 = $rules | Where-Object DisplayName -eq ($rulePrefix+'Block IPv6 egress') | Select-Object -First 1
  foreach ($required in @(@($iface,'Allow','Outbound','tailscale_interface_rule_invalid'),@($transport,'Allow','Outbound','tailscale_transport_rule_invalid'),@($dhcp,'Allow','Outbound','dhcp_rule_invalid'),@($ipv6,'Block','Outbound','ipv6_block_rule_invalid'))) {
    if (-not (Test-RuleShape $required[0] $required[1] $required[2])) { $issues.Add($required[3]) }
  }
  if ($iface -and (Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $iface).InterfaceAlias -notcontains $adapter.Name) { $issues.Add('tailscale_interface_scope_mismatch') }
  if ($transport -and (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $transport).Program -ne $state.TailscaleExe) { $issues.Add('tailscale_transport_program_mismatch') }
  if ($dhcp) {
    $port = Get-NetFirewallPortFilter -AssociatedNetFirewallRule $dhcp
    $service = Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $dhcp
    $ifilter = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $dhcp
    if ($port.Protocol -ne 'UDP' -or $port.LocalPort -ne '68' -or $port.RemotePort -ne '67' -or $service.Service -ne 'Dhcp' -or $ifilter.InterfaceAlias -notcontains $state.EthernetAlias) { $issues.Add('dhcp_exception_scope_mismatch') }
  }
  $overlap = @(Get-NetFirewallRule -Enabled True -Direction Outbound -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.Group -ne $group } | Where-Object {
    $f = Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $_ -ErrorAction SilentlyContinue
    -not $f -or -not $f.InterfaceAlias -or $f.InterfaceAlias -contains 'Any' -or $f.InterfaceAlias -contains $state.EthernetAlias
  })
  if ($overlap.Count) { $issues.Add("non_walnuts_ethernet_allow_rules:$($overlap.Count)") }
  $dns4 = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4).ServerAddresses
  $dns6 = @(Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6).ServerAddresses
  if ((@($dns4) -join ',') -ne (@($config.DnsIPv4) -join ',')) { $issues.Add('tailscale_ipv4_dns_mismatch') }
  if ($dns6.Count) { $issues.Add('tailscale_ipv6_dns_present') }
  if ([bool]$prefs.CorpDNS) { $issues.Add('tailscale_dns_acceptance_enabled') }
  return [pscustomobject]@{ Protected=($issues.Count -eq 0); Issues=@($issues) }
}
function Set-ModeState($state, $mode) {
  if ($PlanOnly) { return }
  $state.Mode=$mode; $state.UpdatedUtc=[DateTime]::UtcNow.ToString('o')
  $state | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath $statePath
}
function Show-Status($state, $adapter, $exe) {
  $ethernetDns=Get-DnsClientServerAddress -InterfaceAlias $config.EthernetAlias -AddressFamily IPv4
  $routes=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
  $exit='unavailable'
  $prefs=$null
  try { $prefs=Get-Prefs $exe; $exit=$prefs.ExitNodeIP } catch { $exit='unavailable: '+$_.Exception.Message }
  $ts4='unavailable'; $ts6='unavailable'
  try { $ts4=(& $exe ip -4 2>$null).Trim(); $ts6=(& $exe ip -6 2>$null).Trim() } catch { }
  $assessment=$null; if($state -and $adapter -and $prefs){$assessment=Get-LockdownAssessment $state $adapter $prefs}
  $category='UNINITIALIZED'
  $directOk=$false
  if($state -and $prefs){
    $profileMismatch=@(Get-NetFirewallProfile | Where-Object {
      $current=$_; $saved=$state.OriginalProfiles | Where-Object Name -eq $current.Name | Select-Object -First 1
      -not $saved -or [string]$saved.DefaultOutboundAction -ne [string]$current.DefaultOutboundAction -or [bool]$saved.Enabled -ne [bool]$current.Enabled
    })
    $directOk=(-not $prefs.ExitNodeIP -and -not $prefs.ExitNodeID -and -not @(Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue).Count -and -not $profileMismatch.Count)
  }
  if($state -and $state.Mode -eq 'DIRECT'){$category=$(if($directOk){'DIRECT'}else{'DEGRADED'})}
  elseif($assessment){
    if(-not $assessment.Protected){$category='DEGRADED'}
    elseif($exit -eq $config.ExitNodeIPv4){$category='VPNBOOK_HEALTHY'}
    elseif($exit){$category='VPNBOOK_BLOCKED'}
    else{$category='ARMED_BLOCKED'}
  }
  [pscustomobject]@{Status=$category; RecordedMode=$(if ($state) {$state.Mode} else {'UNINITIALIZED'}); Computer=$env:COMPUTERNAME; TailscaleAlias=$(if ($adapter) {$adapter.Name} else {'unavailable'})
    TailscaleExitNode=$exit; TailscaleIPv4=$ts4; TailscaleIPv6=$ts6; EthernetDns=($ethernetDns.ServerAddresses -join ',')
    ProtectionConfigured=$(if($assessment){$assessment.Protected}else{$false}); ProtectionIssues=$(if($assessment){$assessment.Issues}else{@('baseline_or_adapter_unavailable')}); DefaultRoutes=@($routes | Select-Object InterfaceAlias,NextHop,RouteMetric)} | ConvertTo-Json -Depth 5
}
function Switch-Direct($state, $emergency=$false) {
  if (-not $ConfirmDirect) { throw 'DIRECT removes VPN protection. Re-run with -ConfirmDirect after reviewing the warning.' }
  if ($emergency -and $EmergencyPhrase -cne 'I UNDERSTAND THIS DISABLES VPN PROTECTION') { throw 'Emergency recovery requires -EmergencyPhrase "I UNDERSTAND THIS DISABLES VPN PROTECTION".' }
  if ($emergency) { Write-Warning 'EMERGENCY: this explicitly disables VPN protection and restores direct ISP access.' } else { Write-Warning 'DIRECT mode removes the pilot kill switch and returns PC-STREAM to normal ISP access.' }
  if ($PlanOnly) { Write-Output 'PLAN: clear exit node; restore DHCP DNS; restore captured firewall outbound defaults; remove only Walnuts pilot rules'; return }
  if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Switch explicitly to unprotected DIRECT mode')) { return }
  Invoke-Tailscale $state @('set','--exit-node=')
  Invoke-Tailscale $state @('set',('--accept-dns={0}' -f $state.OriginalAcceptDNS.ToString().ToLowerInvariant()))
  Set-DnsClientServerAddress -InterfaceAlias $state.EthernetAlias -ResetServerAddresses
  $originalTailscaleDns=@($state.OriginalTailscaleDnsIPv4)+@($state.OriginalTailscaleDnsIPv6)
  if($originalTailscaleDns.Count){Set-DnsClientServerAddress -InterfaceIndex $state.TailscaleIfIndex -ServerAddresses $originalTailscaleDns}
  else{Set-DnsClientServerAddress -InterfaceIndex $state.TailscaleIfIndex -ResetServerAddresses}
  foreach ($profile in $state.OriginalProfiles) {
    Set-NetFirewallProfile -Profile $profile.Name -DefaultOutboundAction ([string]$profile.DefaultOutboundAction)
    if (-not $profile.Enabled) { Set-NetFirewallProfile -Profile $profile.Name -Enabled False }
  }
  Get-NetFirewallRule -Group $group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  Set-ModeState $state 'DIRECT'
}
if ($PlanOnly) { Write-Warning 'PLAN ONLY: no Windows network changes will be made.' }
$adapter=Assert-Target ($Mode -in @('Arm','VPNBOOK')) ($Mode -in @('Arm','VPNBOOK'))
$exe=Get-TailscaleExe
if ($Mode -in @('Status','Verify')) {
  $state=$null
  if (Test-Path -LiteralPath $statePath) { $state=Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json }
  if($Mode -eq 'Status'){ Show-Status $state $adapter $exe; exit 0 }
  if(-not $state -or -not $adapter){ throw 'Cannot verify connectivity without an initialized baseline and active Tailscale adapter' }
  $prefs=Get-Prefs $exe; $assessment=Get-LockdownAssessment $state $adapter $prefs
  if(-not $assessment.Protected -or $prefs.ExitNodeIP -ne $config.ExitNodeIPv4){ throw "Connectivity verification blocked: $($assessment.Issues -join ',')" }
  $dns=Resolve-DnsName -Name 'example.com' -DnsOnly -ErrorAction SilentlyContinue
  $public=(Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8)
  [pscustomobject]@{Configuration='VPNBOOK_HEALTHY';DnsQueryCompleted=($null -ne $dns);PublicIPv4=$public;ExpectedIPv4=$config.ExpectedVpnIPv4;LiveConnectivityVerified=($null -ne $dns -and $public -eq $config.ExpectedVpnIPv4)} | ConvertTo-Json
  exit 0
}
$state=Save-Baseline $adapter $exe ($Mode -eq 'EmergencyDirect')
if ($state.Hostname -ne $env:COMPUTERNAME -or $state.EthernetAlias -ne $config.EthernetAlias -or $state.ClientIPv4 -ne $config.ClientTailscaleIPv4 -or $state.ClientIPv6 -ne $config.ClientTailscaleIPv6) { throw 'Saved pilot baseline identity/interface differs; refusing mode change.' }
if ($Mode -in @('Arm','VPNBOOK')) {
  if (-not $adapter -or $state.TailscaleAlias -ne $adapter.Name) { throw 'Saved Tailscale adapter differs from the active interface; refusing to arm or select VPNBOOK.' }
  $current4 = (& $exe ip -4).Trim()
  $current6 = (& $exe ip -6).Trim()
  if ($LASTEXITCODE -ne 0 -or $current4 -ne $config.ClientTailscaleIPv4 -or $current6 -ne $config.ClientTailscaleIPv6) { throw 'Current Tailscale addresses differ from the reviewed PC-STREAM identity.' }
}
if ($Mode -in @('DIRECT','EmergencyDirect')) { Switch-Direct $state ($Mode -eq 'EmergencyDirect'); exit 0 }
if ($PlanOnly -and $Mode -in @('Arm','VPNBOOK')) { Write-Output 'PLAN: capture baseline; allow Tailscale transport/DHCP; enable outbound default Block; block all IPv6; set approved DNS only on the detected Tailscale interface and disable Tailscale DNS acceptance; reject conflicting Ethernet allow rules'; if ($Mode -eq 'VPNBOOK') { Write-Output 'PLAN: after SethLinux path and tailnet approval, select exit node 100.112.153.81 with LAN access disabled' } else { Write-Output 'PLAN: leave exit node unselected; internet remains blocked' }; exit 0 }
if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Enable PC-STREAM VPNBOOK kill switch and select SethLinux exit node')) { exit 0 }
if ($state.ClientIPv4 -ne $config.ClientTailscaleIPv4 -or $state.ClientIPv6 -ne $config.ClientTailscaleIPv6) { throw 'Captured Tailscale identity does not match approved configuration' }
Add-LockdownRules $state
try {
  # Protection is in force before DNS or exit-node settings change. Errors leave all deny rules installed.
  Invoke-Tailscale $state @('set','--accept-dns=false')
  Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($config.DnsIPv4)
  $assessment=Get-LockdownAssessment $state $adapter (Get-Prefs $exe)
  if (-not $assessment.Protected) { throw "Windows protection verification failed: $($assessment.Issues -join ',')" }
  if ($Mode -eq 'Arm') {
    Set-ModeState $state 'ARMED_BLOCKED'
    Write-Output 'Kill switch armed; no exit node was selected, so public traffic remains blocked.'
    exit 0
  }
  Invoke-Tailscale $state @('set',('--exit-node={0}' -f $config.ExitNodeIPv4),'--exit-node-allow-lan-access=false')
  Set-ModeState $state 'VPNBOOK'
  Write-Output 'VPNBOOK selected under outbound fail-closed protection. Run -Mode Status and the documented acceptance checks.'
} catch {
  Set-ModeState $state 'VPNBOOK_BLOCKED'
  throw "VPNBOOK setup failed; kill switch remains active. Resolve the issue or explicitly choose DIRECT: $_"
}
