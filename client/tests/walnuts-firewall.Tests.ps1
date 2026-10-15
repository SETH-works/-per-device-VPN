. (Join-Path $PSScriptRoot '..\walnuts-firewall.ps1')
function New-TestRule {
  [pscustomobject]@{Name='fixture'; Enabled='True'; Direction='Outbound'; Action='Allow'; Profile=@('Any')
    Program='C:\Windows\System32\svchost.exe'; Service='dnscache'; Protocol='UDP'; RemotePort=@('53'); LocalPort=@('Any')
    RemoteAddress=@('Any'); LocalAddress=@('Any'); InterfaceAlias=@('Any'); InterfaceType=@('Any')
    PrimaryStatus='OK'; EnforcementStatus=@('Full'); PolicyStoreSourceType='Local'; FilterError=$null}
}
Describe 'Effective firewall classification with synthetic filters' {
  $cases=@(
    @{Label='DNS Client UDP 53';Fields=@{};Expected='ConfirmedBypassRisk'},
    @{Label='DiagTrack TCP 443';Fields=@{Service='DiagTrack';Protocol='TCP';RemotePort=@('443')};Expected='ConfirmedBypassRisk'},
    @{Label='Troubleshooting TCP 80 and 443';Fields=@{Service='TroubleshootingSvc';Protocol='TCP';RemotePort=@('80','443')};Expected='ConfirmedBypassRisk'},
    @{Label='browser DoH';Fields=@{Program='C:\Apps\browser.exe';Service='Any';Protocol='TCP';RemotePort=@('443')};Expected='ConfirmedBypassRisk'},
    @{Label='encapsulated IPv6 protocol 41';Fields=@{Program='System';Protocol='41';RemotePort=@('Any')};Expected='ConfirmedBypassRisk'},
    @{Label='native public IPv6';Fields=@{Protocol='TCP';RemoteAddress=@('2606:4700:4700::1111')};Expected='ConfirmedBypassRisk'},
    @{Label='Hyper-V only';Fields=@{InterfaceAlias=@('vEthernet (Default Switch)')};Expected='Restricted'},
    @{Label='multiple interfaces including Ethernet';Fields=@{InterfaceAlias=@('vEthernet (Default Switch)','Ethernet')};Expected='ConfirmedBypassRisk'},
    @{Label='wildcard Ethernet alias';Fields=@{InterfaceAlias=@('Ether*')};Expected='ConfirmedBypassRisk'},
    @{Label='Wireless only';Fields=@{InterfaceType=@('Wireless')};Expected='Restricted'},
    @{Label='disabled';Fields=@{Enabled='False'};Expected='Restricted'},
    @{Label='inbound';Fields=@{Direction='Inbound'};Expected='Restricted'},
    @{Label='explicit block versus transport allow';Fields=@{Action='Block';InterfaceAlias=@('Ethernet')};Expected='PotentialBypass'},
    @{Label='DNS dynamic keyword';Fields=@{RemoteAddress=@('DNS')};Expected='PotentialBypass'},
    @{Label='LocalSubnet keyword';Fields=@{RemoteAddress=@('LocalSubnet')};Expected='PotentialBypass'},
    @{Label='link-local IPv6';Fields=@{RemoteAddress=@('fe80::1')};Expected='Restricted'},
    @{Label='mixed local and public addresses';Fields=@{RemoteAddress=@('fe80::1','1.1.1.1')};Expected='ConfirmedBypassRisk'},
    @{Label='filter query failure';Fields=@{FilterError='access denied'};Expected='PotentialBypass'},
    @{Label='missing interface scope';Fields=@{InterfaceAlias=@()};Expected='PotentialBypass'},
    @{Label='unresolved effective enforcement';Fields=@{EnforcementStatus=@('Unknown')};Expected='PotentialBypass'},
    @{Label='TCP DERP service candidate';Fields=@{Program='C:\Program Files\Tailscale\tailscaled.exe';Service='Tailscale';InterfaceAlias=@('Ethernet');Protocol='TCP';RemotePort=@('443')};Expected='ApprovedUnderlayException'},
    @{Label='UDP endpoint roaming service candidate';Fields=@{Program='C:\Program Files\Tailscale\tailscaled.exe';Service='Tailscale';InterfaceAlias=@('Ethernet');RemotePort=@('Any')};Expected='ApprovedUnderlayException'},
    @{Label='CLI is not service transport';Fields=@{Program='C:\Program Files\Tailscale\tailscale.exe';Service='Tailscale'};Expected='ConfirmedBypassRisk'},
    @{Label='service binary without service restriction';Fields=@{Program='C:\Program Files\Tailscale\tailscaled.exe';Service='Any'};Expected='ConfirmedBypassRisk'},
    @{Label='managed policy rule';Fields=@{PolicyStoreSourceType='GroupPolicy'};Expected='ConfirmedBypassRisk'}
  )
  foreach($case in $cases){
    It $case.Label {
      $r=New-TestRule
      foreach($key in $case.Fields.Keys){$r.$key=$case.Fields[$key]}
      $a=Get-WalnutsRuleAssessment $r 'Ethernet' 'C:\Program Files\Tailscale\tailscaled.exe'
      $a.Category | Should Be $case.Expected
      [string]::IsNullOrEmpty($a.Reason) | Should Be $false
    }
  }
}
Describe 'Service identity and deployment gate' {
  It 'resolves quoted SCM service path separately from the CLI' {
    $s=Get-WalnutsServiceIdentity ([pscustomobject]@{Name='Tailscale';PathName='"C:\Program Files\Tailscale\tailscaled.exe" --runservice';State='Running';ProcessId=123})
    $s.Program | Should Be 'C:\Program Files\Tailscale\tailscaled.exe'
  }
  It 'rejects ambiguous unquoted SCM paths' {
    $rejected=$false
    try {Get-WalnutsServiceIdentity ([pscustomobject]@{PathName='C:\Program Files\Tailscale\tailscaled.exe'})} catch {$rejected=$true}
    $rejected | Should Be $true
  }
  It 'never treats missing rules or stale state as protection' {
    $s=[pscustomobject]@{Rules=@();Profiles=@();Adapters=@();Connections=@();Service=$null;Errors=@('capture failed')}
    $a=Get-WalnutsEgressAudit $s 'Ethernet'
    $a.Protected | Should Be $false
    $a.Ready | Should Be $false
    ($a.Blockers -join ';') | Should Match 'capture failed'
  }
  It 'blocks on service restart disappearance and changed profiles or managed policy' {
    $s=[pscustomobject]@{Rules=@();Profiles=@([pscustomobject]@{Name='Private';Enabled='True';DefaultOutboundAction='Allow';AllowLocalFirewallRules='False'});Adapters=@();Connections=@();Service=[pscustomobject]@{State='Stopped'};Errors=@()}
    $a=Get-WalnutsEgressAudit $s 'Ethernet'
    $a.Ready | Should Be $false
    ($a.Blockers -join ';') | Should Match 'merge is disabled'
    ($a.Blockers -join ';') | Should Match 'running state unavailable'
  }
}

Describe 'Legacy recovery validates before any mutation' {
  function New-TestBaseline {
    [pscustomobject]@{Version=2;Hostname='STREAM';EthernetAlias='Ethernet';ClientIPv4='100.70.142.17';ClientIPv6='fd7a:115c:a1e0::7f3b:8e11'
      TailscaleAlias='Tailscale';TailscaleIfIndex=42;OriginalAcceptDNS=$true;TailscaleExe='C:\Program Files\Tailscale\tailscale.exe'
      OriginalTailscaleDnsIPv4=@('100.100.100.100');OriginalTailscaleDnsIPv6=@()
      OriginalProfiles=@(foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;Enabled=$true;DefaultOutboundAction='Allow'}})}
  }
  $cfg=[pscustomobject]@{EthernetAlias='Ethernet';ClientTailscaleIPv4='100.70.142.17';ClientTailscaleIPv6='fd7a:115c:a1e0::7f3b:8e11'}
  It 'accepts a complete captured baseline for later explicit confirmation' {
    $failed=$false;try{Assert-WalnutsRecoveryBaseline (New-TestBaseline) $cfg 'STREAM'}catch{$failed=$true}
    $failed | Should Be $false
  }
  foreach($field in @('Version','Hostname','EthernetAlias','TailscaleIfIndex','OriginalAcceptDNS','OriginalProfiles','OriginalTailscaleDnsIPv4')) {
    It ('rejects corrupt or partial '+$field) {
      $s=New-TestBaseline
      $s.$field='corrupt'
      $rejected=$false;try{Assert-WalnutsRecoveryBaseline $s $cfg 'STREAM'}catch{$rejected=$true}
      $rejected | Should Be $true
    }
  }
  It 'rejects an absent journal instead of synthesizing DIRECT from live state' {
    $rejected=$false;try{Assert-WalnutsRecoveryBaseline $null $cfg 'STREAM'}catch{$rejected=$true}
    $rejected | Should Be $true
  }
}

Describe 'Explicit recovery failure behavior with inert command substitutes' {
  # Load only the existing recovery function AST, never the controller entrypoint.
  $tokens=$null; $parseErrors=$null
  $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\walnuts-client.ps1'),[ref]$tokens,[ref]$parseErrors)
  $definition=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Switch-Direct'},$true)
  Invoke-Expression $definition.Extent.Text
  function Get-NetAdapter { [pscustomobject]@{Name='Tailscale';InterfaceDescription='Tailscale Tunnel';ifIndex=42} }
  function Get-NetFirewallRule { @() }
  function Invoke-Tailscale { throw 'MUTATION_ATTEMPT' }
  function Set-DnsClientServerAddress { throw 'MUTATION_ATTEMPT' }
  function Set-NetFirewallProfile { throw 'MUTATION_ATTEMPT' }
  function Remove-NetFirewallRule { throw 'MUTATION_ATTEMPT' }
  $group='Project Walnuts PC-STREAM pilot'
  $exe='C:\Program Files\Tailscale\tailscale.exe'
  $recoveryState=[pscustomobject]@{TailscaleAlias='Tailscale';TailscaleIfIndex=42;TailscaleExe=$exe
    OriginalProfiles=@(foreach($name in @('Domain','Private','Public')){[pscustomobject]@{Name=$name;Enabled=$true;DefaultOutboundAction='Allow'}})}
  It 'requires explicit DIRECT acknowledgement before any operation' {
    $ConfirmDirect=$false; $PlanOnly=$false
    $message='';try{Switch-Direct $recoveryState}catch{$message=$_.Exception.Message}
    $message | Should Match 'ConfirmDirect'
    $message | Should Not Match 'MUTATION_ATTEMPT'
  }
  It 'requires the emergency owner phrase without silently dropping protection' {
    $ConfirmDirect=$true; $EmergencyPhrase='wrong'; $PlanOnly=$false
    $message='';try{Switch-Direct $recoveryState $true}catch{$message=$_.Exception.Message}
    $message | Should Match 'Emergency recovery requires'
    $message | Should Not Match 'MUTATION_ATTEMPT'
  }
  It 'rejects a changed Tailscale interface index before DNS or firewall writes' {
    $ConfirmDirect=$true; $PlanOnly=$false; $recoveryState.TailscaleIfIndex=43
    $message='';try{Switch-Direct $recoveryState}catch{$message=$_.Exception.Message}
    $recoveryState.TailscaleIfIndex=42
    $message | Should Match 'stale interface index'
    $message | Should Not Match 'MUTATION_ATTEMPT'
  }
  It 'keeps a partial legacy installation intact without an exact ownership manifest' {
    function Get-NetFirewallRule { [pscustomobject]@{DisplayName='Walnuts Pilot DHCP renew'} }
    $ConfirmDirect=$true; $PlanOnly=$false
    $message='';try{Switch-Direct $recoveryState}catch{$message=$_.Exception.Message}
    $message | Should Match 'owned-rule GUID manifest'
    $message | Should Not Match 'MUTATION_ATTEMPT'
  }
  It 'produces a recovery preview without changing DNS profiles or rules' {
    function Get-NetFirewallRule { @() }
    $ConfirmDirect=$true; $PlanOnly=$true
    $output=Switch-Direct $recoveryState
    $output | Should Match 'PLAN:'
  }
}
