#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [Parameter(Mandatory=$true)][ValidateSet('BackendPlan','BackendStatus','Audit','Status','Verify','Arm','VPNBOOK','DIRECT','EmergencyDirect')][string]$Mode,
  [switch]$PlanOnly,
  [switch]$ConfirmDirect,
  [string]$EmergencyPhrase,
  [switch]$DisposableVm,
  [guid]$DeploymentId,
  [string]$ServerHealthPath,
  [string]$ConfigPath = "$PSScriptRoot\pilot-client.json"
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\walnuts-firewall.ps1"
. "$PSScriptRoot\walnuts-wfp.ps1"
$config = Get-Content -Raw -LiteralPath $ConfigPath | ConvertFrom-Json
$stateDir = Join-Path $env:ProgramData 'Walnuts'
$statePath = Join-Path $stateDir 'pc-stream-pilot.json'
$group = 'Project Walnuts PC-STREAM pilot'
$rulePrefix = 'Walnuts Pilot '

if($Mode -in @('BackendPlan','BackendStatus')) {
  $operation=if($Mode -eq 'BackendPlan'){'plan'}else{'status'}
  Invoke-WalnutsBackend $config @($operation) | ConvertTo-Json -Depth 20
  exit 0
}
if($DisposableVm) {
  if($Mode -eq 'EmergencyDirect' -and $EmergencyPhrase -cne 'I UNDERSTAND THIS DISABLES VPN PROTECTION'){throw 'Emergency recovery requires the documented exact acknowledgement.'}
  if(-not $PlanOnly -and -not $PSCmdlet.ShouldProcess($env:COMPUTERNAME,'Change only the explicitly identified disposable lab VM using native WFP')){exit 0}
  Invoke-WalnutsLabMode $config $Mode $DeploymentId -PlanOnly:$PlanOnly -ConfirmDirect:$ConfirmDirect -ServerHealthPath $ServerHealthPath | ConvertTo-Json -Depth 24
  exit 0
}

# Security gate: default Block loses to existing explicit allows; a blanket
# Ethernet block also defeats transport allows. No tested backend exists yet.
# Never capture a new baseline, mutate settings or probe public connectivity
# when the requested protection boundary cannot be established.
if ($Mode -in @('Arm','VPNBOOK','Verify')) {
  [pscustomobject]@{Status='DEGRADED'; Protected=$false; DeploymentBlocked=$true; ChangesApplied=$false
    RequestedMode=$Mode; PlanOnly=[bool]$PlanOnly
    Reason='The native WFP lab backend is not packet-validated for production. Default Block plus allow exceptions cannot establish the required boundary.'
    PlannedDns=[pscustomobject]@{Interface='Detected Tailscale virtual interface';IPv4=@('1.1.1.1','8.8.8.8');AcceptDns=$false;Ethernet='DHCP'}} | ConvertTo-Json -Depth 6
  exit 2
}
if ($Mode -eq 'Audit') {
  if ($env:COMPUTERNAME -ne $config.ClientHostname) { throw 'Wrong PC for this configuration' }
  Get-WalnutsEgressAudit (Get-WalnutsFirewallSnapshot) $config.EthernetAlias | ConvertTo-Json -Depth 12
  exit 2
}

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
  $identity = Get-WalnutsServiceIdentity $svc
  $path = $identity.Program
  $candidate = Join-Path (Split-Path $path) 'tailscale.exe'
  if (-not (Test-Path -LiteralPath $candidate)) { throw "Could not resolve trusted tailscale.exe beside $path" }
  return $candidate
}
function Get-Prefs($exe) {
  $raw = & $exe debug prefs 2>$null
  if ($LASTEXITCODE -ne 0) { throw 'tailscale debug prefs failed' }
  return ($raw | ConvertFrom-Json)
}
function Invoke-Tailscale($state, [string[]]$Arguments) {
  if ($PlanOnly) { Write-Output ("PLAN: {0} {1}" -f $state.TailscaleExe, ($Arguments -join ' ')); return }
  & $state.TailscaleExe @Arguments
  if ($LASTEXITCODE -ne 0) { throw "Tailscale command failed: $($Arguments -join ' ')" }
}
function Set-ModeState($state, $mode) {
  if ($PlanOnly) { return }
  $state.Mode=$mode; $state.UpdatedUtc=[DateTime]::UtcNow.ToString('o')
  $state | ConvertTo-Json -Depth 6 | Set-Content -Encoding utf8 -LiteralPath $statePath
}
function Show-Status($state, $adapter, $exe) {
  $audit=Get-WalnutsEgressAudit (Get-WalnutsFirewallSnapshot) $config.EthernetAlias
  $ethernetDns=Get-DnsClientServerAddress -InterfaceAlias $config.EthernetAlias -AddressFamily IPv4
  $routes=Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue
  $exit='unavailable'
  $prefs=$null
  try { $prefs=Get-Prefs $exe; $exit=$prefs.ExitNodeIP } catch { $exit='unavailable: '+$_.Exception.Message }
  $ts4='unavailable'; $ts6='unavailable'
  try { $ts4=(& $exe ip -4 2>$null).Trim(); $ts6=(& $exe ip -6 2>$null).Trim() } catch { }
  # Reserved mode vocabulary; this release cannot emit a protected category.
  $protectedCategories=@('ARMED_BLOCKED','VPNBOOK_HEALTHY','VPNBOOK_BLOCKED')
  $category='UNINITIALIZED'
  $directOk=$false
  if($state -and $prefs){
    $effectiveProfiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
    $profileMismatch=@($effectiveProfiles | Where-Object {
      $current=$_; $saved=$state.OriginalProfiles | Where-Object Name -eq $current.Name | Select-Object -First 1
      -not $saved -or [string]$saved.DefaultOutboundAction -ne [string]$current.DefaultOutboundAction -or [bool]$saved.Enabled -ne [bool]$current.Enabled
    })
    $dnsDhcp=$false
    try {
      $eth=Get-NetAdapter -Name $config.EthernetAlias -ErrorAction Stop
      $guid=[string]$eth.InterfaceGuid
      if(-not $guid){throw 'Ethernet GUID unavailable'}
      $v4=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\'+$guid) -ErrorAction Stop
      $v6=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\'+$guid) -ErrorAction Stop
      $dnsDhcp=(-not $v4.NameServer -and -not $v6.NameServer)
    } catch {$dnsDhcp=$false}
    $directOk=($effectiveProfiles.Count -eq 3 -and $dnsDhcp -and [bool]$prefs.CorpDNS -eq [bool]$state.OriginalAcceptDNS -and -not $prefs.ExitNodeIP -and -not $prefs.ExitNodeID -and -not @(Get-NetFirewallRule -PolicyStore ActiveStore -Group $group -ErrorAction SilentlyContinue).Count -and -not $profileMismatch.Count)
  }
  if($state -and $state.Mode -eq 'DIRECT'){$category=$(if($directOk){'DIRECT'}else{'DEGRADED'})}
  if($state -and $state.Mode -ne 'DIRECT'){$category='DEGRADED'}
  [pscustomobject]@{Status=$category; Audit=$audit; Protected=$false; DeploymentBlocked=$true; LiveConnectivityVerified=$false; RecordedMode=$(if ($state) {$state.Mode} else {'UNINITIALIZED'}); Computer=$env:COMPUTERNAME; TailscaleAlias=$(if ($adapter) {$adapter.Name} else {'unavailable'})
    TailscaleExitNode=$exit; TailscaleIPv4=$ts4; TailscaleIPv6=$ts6; EthernetDns=($ethernetDns.ServerAddresses -join ',')
    ProtectionConfigured=$false; ProtectionIssues=@('Independent underlay enforcement is unavailable.'); DefaultRoutes=@($routes | Select-Object InterfaceAlias,NextHop,RouteMetric)} | ConvertTo-Json -Depth 14
}
function Switch-Direct($state, $emergency=$false) {
  if (-not $ConfirmDirect) { throw 'DIRECT removes VPN protection. Re-run with -ConfirmDirect after reviewing the warning.' }
  if ($emergency -and $EmergencyPhrase -cne 'I UNDERSTAND THIS DISABLES VPN PROTECTION') { throw 'Emergency recovery requires -EmergencyPhrase "I UNDERSTAND THIS DISABLES VPN PROTECTION".' }
  if ($emergency) { Write-Warning 'EMERGENCY: this explicitly disables VPN protection and restores direct ISP access.' } else { Write-Warning 'DIRECT mode removes the pilot kill switch and returns PC-STREAM to normal ISP access.' }
  $ts=@(Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'Tailscale' -and $_.Name -eq $state.TailscaleAlias -and $_.ifIndex -eq $state.TailscaleIfIndex})
  if($ts.Count -ne 1){throw 'Captured Tailscale interface changed; refusing DNS writes to a stale interface index.'}
  $legacyRules=@(Get-NetFirewallRule -PolicyStore PersistentStore -Group $group -ErrorAction SilentlyContinue)
  $knownNames=@('Walnuts Pilot Tailscale interface','Walnuts Pilot Tailscale transport','Walnuts Pilot DHCP renew','Walnuts Pilot Block IPv6 egress')
  if(@($legacyRules | Where-Object {$_.DisplayName -notin $knownNames}).Count){throw 'Unknown rule in Walnuts group; refusing group-wide recovery.'}
  if($exe -ne $state.TailscaleExe){throw 'Tailscale installation changed; review recovery path before execution.'}
  if(@($state.OriginalProfiles.Name | Sort-Object -Unique).Count -ne 3 -or @($state.OriginalProfiles | Where-Object {$_.Name -notin @('Domain','Private','Public') -or [string]$_.DefaultOutboundAction -notin @('Allow','Block','NotConfigured')}).Count){throw 'Invalid captured firewall profile values.'}
  # The old journal did not record rule GUIDs. Refuse automatic deletion when
  # ownership cannot be proved; an owner must inventory and approve exact IDs.
  if($legacyRules.Count){throw 'Legacy baseline has no owned-rule GUID manifest. Exact rule recovery requires a reviewed manual change plan; no settings were changed.'}
  if ($PlanOnly) { Write-Output 'PLAN: clear exit node; restore DHCP DNS and captured Tailscale DNS; restore captured firewall profiles; no rule deletion without owned-rule GUIDs'; return }
  if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Switch explicitly to unprotected DIRECT mode')) { return }
  Invoke-Tailscale $state @('set','--exit-node=')
  Set-DnsClientServerAddress -InterfaceAlias $state.EthernetAlias -ResetServerAddresses
  $originalTailscaleDns=@($state.OriginalTailscaleDnsIPv4)+@($state.OriginalTailscaleDnsIPv6)
  if($originalTailscaleDns.Count){Set-DnsClientServerAddress -InterfaceIndex $state.TailscaleIfIndex -ServerAddresses $originalTailscaleDns}
  else{Set-DnsClientServerAddress -InterfaceIndex $state.TailscaleIfIndex -ResetServerAddresses}
  Invoke-Tailscale $state @('set',('--accept-dns={0}' -f $state.OriginalAcceptDNS.ToString().ToLowerInvariant()))
  foreach ($profile in $state.OriginalProfiles) {
    Set-NetFirewallProfile -Profile $profile.Name -DefaultOutboundAction ([string]$profile.DefaultOutboundAction)
    Set-NetFirewallProfile -Profile $profile.Name -Enabled $profile.Enabled
  }
  $legacyRules | Remove-NetFirewallRule
  Set-ModeState $state 'DIRECT'
}
if ($PlanOnly) { Write-Warning 'PLAN ONLY: no Windows network changes will be made.' }
if ($Mode -eq 'Status') {
  try {
    $state=$null
    if (Test-Path -LiteralPath $statePath) { $state=Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json }
    $adapter=Assert-Target $false $false
    $exe=Get-TailscaleExe
    Show-Status $state $adapter $exe
  } catch {
    [pscustomobject]@{Status='DEGRADED';Protected=$false;DeploymentBlocked=$true;LiveConnectivityVerified=$false;Reason=$_.Exception.Message} | ConvertTo-Json
  }
  exit 0
}
$adapter=Assert-Target $false $false
$exe=Get-TailscaleExe
if(-not (Test-Path -LiteralPath $statePath)){throw 'No captured baseline exists. Refusing to invent recovery settings from the current network.'}
$state=Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
Assert-WalnutsRecoveryBaseline $state $config $env:COMPUTERNAME
if ($Mode -in @('DIRECT','EmergencyDirect')) { Switch-Direct $state ($Mode -eq 'EmergencyDirect'); exit 0 }
throw 'Unsupported operation; protection activation is disabled.'
