. (Join-Path $PSScriptRoot '..\walnuts-firewall.ps1')
. (Join-Path $PSScriptRoot '..\walnuts-wfp.ps1')

Describe 'Disposable-VM orchestration with inert network substitutes' {
  function New-LabFixtures {
    $script:deployment=[guid]'ec2173e9-996f-4341-8a96-4bb692848903'
    $script:tunnel=[guid]'3ce4918b-52f0-47f2-aaab-107496bf4211'
    $script:underlay=[guid]'e6a68ec7-053f-412e-9aaf-158a257ea8dd'
    $script:cfg=[pscustomobject]@{ClientHostname='WALNUTS-LAB';EthernetAlias='Ethernet';ExitNodeIPv4='100.112.153.81'}
    $script:nativeMode='ARMED_BLOCKED'; $script:hasBaseline=$false; $script:liveValid=$true; $script:failInstall=$false
    $script:effects=[Collections.Generic.List[string]]::new()
    $script:commands=[Collections.Generic.List[string]]::new()
    $script:baseline=[pscustomobject]@{Version=3;Deployment=$deployment.ToString();TunnelAdapter=$tunnel.ToString();UnderlayAdapter=$underlay.ToString();AcceptDns=$true;AcceptRoutes=$true;Dns4=@('100.100.100.100');Dns6=@();Mode='ARMED_BLOCKED'}
  }
  function In-Lab([scriptblock]$Test) {
    $original=$env:COMPUTERNAME
    try{$env:COMPUTERNAME='WALNUTS-LAB'; & $Test}finally{$env:COMPUTERNAME=$original}
  }
  function Invoke-WalnutsBackend($Config,[string[]]$Arguments) {
    $script:commands.Add($Arguments[0])
    if($Arguments[0] -eq 'plan'){return [pscustomobject]@{Manifest=[pscustomobject]@{Configuration=[pscustomobject]@{Deployment=$deployment.ToString();TunnelAdapter=$tunnel.ToString();UnderlayAdapter=$underlay.ToString();Mode=$nativeMode}}}}
    if($Arguments[0] -eq 'verify'){return [pscustomobject]@{Schema=1;FilterSetVerified=$liveValid;IdentityVerified=$true;IntentMatches=$true;Snapshot=[pscustomobject]@{Manifest=[pscustomobject]@{Configuration=[pscustomobject]@{Mode='ARMED_BLOCKED'}}}}}
    if($Arguments[0] -eq 'arm' -and $failInstall){throw 'Injected native install failure'}
    if($Arguments[0] -eq 'remove'){return [pscustomobject]@{Removed=$true}}
    return [pscustomobject]@{FilterSetVerified=$true}
  }
  function Get-CimInstance([string]$ClassName) {
    if($ClassName -eq 'Win32_ComputerSystem'){return [pscustomobject]@{Model='Virtual Machine'}}
    return [pscustomobject]@{Name='Tailscale';PathName='"C:\Program Files\Tailscale\tailscaled.exe"';State='Running';ProcessId=123}
  }
  function Get-NetAdapter([string]$Name) {
    if($Name){return [pscustomobject]@{Name='Ethernet';InterfaceGuid=$underlay;ifIndex=7}}
    return [pscustomobject]@{Name='Tailscale';InterfaceDescription='Tailscale Tunnel';Status='Up';InterfaceGuid=$tunnel;ifIndex=42}
  }
  function Test-Path {return $hasBaseline}
  function Get-Content([string]$LiteralPath) {
    if($LiteralPath -like '*client-baseline.json'){return ($baseline | ConvertTo-Json -Depth 8)}
    return ([pscustomobject]@{CapturedUtc=[DateTimeOffset]::UtcNow.ToString('o');Health=[pscustomobject]@{healthy=$true;guard_present=$true}} | ConvertTo-Json -Depth 8)
  }
  function Invoke-WalnutsLabTailscale([string]$Cli,[string[]]$Values) {
    if($Values[0] -eq 'debug'){return '{"CorpDNS":true,"RouteAll":true,"ExitNodeIP":"","ExitNodeID":""}'}
    if($Values[0] -eq 'status'){return '{"ExitNodeStatus":{"TailscaleIPs":["100.112.153.81"],"Online":true}}'}
    $script:effects.Add('tailscale:'+($Values -join ' '))
  }
  function Set-DnsClientServerAddress {$script:effects.Add('dns')}
  function Set-Content {$script:effects.Add('state-write')}
  function Set-NetFirewallProfile {throw 'FORBIDDEN_DEFENDER_MUTATION'}

  It 'does not create a baseline or change network settings in a lab Arm preview' {
    New-LabFixtures
    In-Lab {
      $result=Invoke-WalnutsLabMode $cfg 'Arm' $deployment -PlanOnly
      $result.ChangesApplied | Should Be $false
      $effects.Count | Should Be 0
      ($commands -join ',') | Should Be 'plan'
    }
  }
  It 'blocks VPNBOOK when real filter evidence is incomplete before changing DNS or exit' {
    New-LabFixtures; $script:hasBaseline=$true; $script:nativeMode='VPNBOOK'; $script:liveValid=$false
    In-Lab {
      $message='';try{Invoke-WalnutsLabMode $cfg 'VPNBOOK' $deployment -ServerHealthPath 'fixture-health'}catch{$message=$_.Exception.Message}
      $message | Should Match 'verified ARMED'
      $effects.Count | Should Be 0
      ($commands -join ',') | Should Not Match 'arm|remove'
    }
  }
  It 'never removes the native block or returns DIRECT after a failed VPN transition' {
    New-LabFixtures; $script:hasBaseline=$true; $script:nativeMode='VPNBOOK'; $script:failInstall=$true
    In-Lab {
      $message='';try{Invoke-WalnutsLabMode $cfg 'VPNBOOK' $deployment -ServerHealthPath 'fixture-health'}catch{$message=$_.Exception.Message}
      $message | Should Match 'Injected native install failure'
      ($commands -join ',') | Should Not Match 'remove'
      ($effects -join ',') | Should Not Match 'state-write|--exit-node=,'
      $baseline.Mode | Should Be 'ARMED_BLOCKED'
    }
  }
  It 'requires explicit confirmation for lab DIRECT' {
    New-LabFixtures; $script:hasBaseline=$true
    In-Lab {
      $message='';try{Invoke-WalnutsLabMode $cfg 'DIRECT' $deployment}catch{$message=$_.Exception.Message}
      $message | Should Match 'explicit owner confirmation'
      $effects.Count | Should Be 0
    }
  }
  It 'rejects corrupt captured booleans without changing settings' {
    New-LabFixtures; $script:hasBaseline=$true; $script:baseline.AcceptDns='false'
    In-Lab {
      $message='';try{Invoke-WalnutsLabMode $cfg 'DIRECT' $deployment -ConfirmDirect}catch{$message=$_.Exception.Message}
      $message | Should Match 'Corrupt lab baseline'
      $effects.Count | Should Be 0
    }
  }
}
