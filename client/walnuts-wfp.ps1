# Orchestration only. Native WFP remains the enforcement authority. No probe or
# mutation occurs when this file is dot-sourced.
function Invoke-WalnutsLabTailscale([string]$Cli,[string[]]$Values) {
  $raw=& $Cli @Values
  if($LASTEXITCODE -ne 0){throw 'Tailscale lab command failed; WFP filters retained.'}
  return $raw
}
function Invoke-WalnutsBackend($Config,[string[]]$Arguments) {
  $path=Join-Path $env:ProgramFiles 'WalnutsWfp\Walnuts.Wfp.exe'
  if($Config.HelperSha256 -notmatch '^[a-fA-F0-9]{64}$'){throw 'A reviewed helper SHA256 pin is required.'}
  if((Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash -ne $Config.HelperSha256){throw 'Installed helper hash mismatch.'}
  foreach($name in @('Walnuts.Wfp.dll','Walnuts.Wfp.deps.json','Walnuts.Wfp.runtimeconfig.json')) {
    $pin=$Config.HelperFiles.$name
    if($pin -notmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath (Join-Path (Split-Path $path) $name) -Algorithm SHA256 -ErrorAction Stop).Hash -ne $pin){throw "Helper companion file pin mismatch: $name"}
  }
  $acl=Get-Acl -LiteralPath (Split-Path $path) -ErrorAction Stop
  foreach($ace in $acl.Access){
    if($ace.AccessControlType -ne 'Allow'){continue}
    $sid=$ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    $write=[Security.AccessControl.FileSystemRights]'Write,Delete,DeleteSubdirectoriesAndFiles,ChangePermissions,TakeOwnership'
    if(($ace.FileSystemRights -band $write) -and $sid -notin @('S-1-5-18','S-1-5-32-544')){throw 'Helper directory is writable by an untrusted principal.'}
  }
  $raw=& $path @Arguments
  $code=$LASTEXITCODE
  $result=($raw -join "`n") | ConvertFrom-Json -ErrorAction Stop
  if($result.Schema -ne 1){throw 'Unknown helper JSON protocol.'}
  if($code -ne 0){throw "WFP helper blocked operation ($code): $($result.Error)"}
  return $result
}

function Test-WalnutsBackendEvidence($Evidence) {
  # Process launch, an exit code and named filters are insufficient. Even a
  # verified lab filter set is not a production protection attestation.
  return ($Evidence.Schema -eq 1 -and $Evidence.FilterSetVerified -is [bool] -and $Evidence.FilterSetVerified -and
          $Evidence.IdentityVerified -is [bool] -and $Evidence.IdentityVerified -and
          $Evidence.IntentMatches -is [bool] -and $Evidence.IntentMatches -and $null -ne $Evidence.Snapshot.Manifest)
}

function Invoke-WalnutsLabMode($Config,[string]$RequestedMode,[guid]$Deployment,[switch]$PlanOnly,[switch]$ConfirmDirect,[string]$ServerHealthPath) {
  if($env:COMPUTERNAME -eq 'STREAM' -or $env:COMPUTERNAME -ne $Config.ClientHostname){throw 'Disposable lab hostname required; production STREAM is refused.'}
  $vm=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
  if($vm.Model -notmatch 'Virtual Machine|VirtualBox|VMware|KVM|QEMU'){throw 'An existing disposable VM is required.'}
  $plan=Invoke-WalnutsBackend $Config @('plan')
  if($plan.Manifest.Configuration.Deployment -ne $Deployment.ToString()){throw 'Explicit lab deployment ID differs from helper configuration.'}
  $root=Join-Path $env:ProgramData 'WalnutsWfp'
  $baselinePath=Join-Path $root 'client-baseline.json'
  $ts=@(Get-NetAdapter | Where-Object {$_.InterfaceDescription -match 'Tailscale' -and $_.Status -eq 'Up'})
  if($ts.Count -ne 1 -or [guid]$ts[0].InterfaceGuid -ne [guid]$plan.Manifest.Configuration.TunnelAdapter){throw 'Tailscale adapter GUID mismatch.'}
  $ethernet=Get-NetAdapter -Name $Config.EthernetAlias -ErrorAction Stop
  if([guid]$ethernet.InterfaceGuid -ne [guid]$plan.Manifest.Configuration.UnderlayAdapter){throw 'Reviewed underlay GUID mismatch.'}
  $svc=Get-WalnutsServiceIdentity (Get-CimInstance Win32_Service -Filter "Name='Tailscale'")
  $cli=Join-Path (Split-Path $svc.Program) 'tailscale.exe'
  function Set-LabPrefs([string[]]$Values){Invoke-WalnutsLabTailscale $cli $Values | Out-Null}
  $prefsRaw=Invoke-WalnutsLabTailscale $cli @('debug','prefs')
  $prefs=$prefsRaw | ConvertFrom-Json
  $state=$null
  if(Test-Path -LiteralPath $baselinePath){$state=Get-Content -Raw -LiteralPath $baselinePath | ConvertFrom-Json}
  if($state -and ($state.Version -ne 3 -or $state.Deployment -ne $Deployment.ToString() -or [guid]$state.TunnelAdapter -ne [guid]$ts[0].InterfaceGuid -or [guid]$state.UnderlayAdapter -ne [guid]$ethernet.InterfaceGuid)){throw 'Lab baseline identity differs.'}
  if($state -and ($state.AcceptDns -isnot [bool] -or $state.AcceptRoutes -isnot [bool])){throw 'Corrupt lab baseline preferences; do not coerce string booleans.'}
  if($RequestedMode -in @('DIRECT','EmergencyDirect')) {
    if(-not $ConfirmDirect -or -not $state){throw 'Lab DIRECT needs explicit owner confirmation and captured state.'}
    if($PlanOnly){return [pscustomobject]@{ChangesApplied=$false;Plan='Restore captured DNS/preferences under WFP block, then remove exact owned native objects.'}}
    # Keep the native block until exit selection and DNS restoration succeed.
    Set-LabPrefs @('set','--exit-node=')
    $oldDns=@($state.Dns4)+@($state.Dns6)
    if($oldDns.Count){Set-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -ServerAddresses $oldDns}
    else{Set-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -ResetServerAddresses}
    Set-DnsClientServerAddress -InterfaceIndex $ethernet.ifIndex -ResetServerAddresses
    Set-LabPrefs @('set',('--accept-dns='+([bool]$state.AcceptDns).ToString().ToLowerInvariant()),('--accept-routes='+([bool]$state.AcceptRoutes).ToString().ToLowerInvariant()))
    $removed=Invoke-WalnutsBackend $Config @('remove','--disposable-vm',$Deployment.ToString(),'--confirm-direct')
    if($removed.Removed -ne $true){throw 'Native removal not verified.'}
    $state.Mode='DIRECT';$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baselinePath -Encoding utf8
    return [pscustomobject]@{Status='DIRECT';LabOnly=$true;Protected=$false;ProductionReady=$false}
  }
  if($RequestedMode -eq 'Verify') {
    $live=Invoke-WalnutsBackend $Config @('verify')
    if(-not (Test-WalnutsBackendEvidence $live)){throw 'Native evidence incomplete; no public connectivity probe attempted.'}
    $issues=[Collections.Generic.List[string]]::new()
    $public=$null; $dnsAnswered=$false; $ipv6AttemptSucceeded=$false
    if($live.Snapshot.Manifest.Configuration.Mode -eq 'VPNBOOK') {
      $tailStatus=(Invoke-WalnutsLabTailscale $cli @('status','--json')) | ConvertFrom-Json
      if($tailStatus.ExitNodeStatus.TailscaleIPs -notcontains $Config.ExitNodeIPv4 -or $tailStatus.ExitNodeStatus.Online -ne $true){$issues.Add('Observed exit-node selection/online state differs.')}
      $actualDns=@((Get-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -AddressFamily IPv4).ServerAddresses)
      if(($actualDns -join ',') -ne '1.1.1.1,8.8.8.8' -or $prefs.CorpDNS){$issues.Add('Observed DNS configuration differs.')}
      if(@((Get-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -AddressFamily IPv6).ServerAddresses).Count){$issues.Add('Unexpected IPv6 DNS servers on Tailscale adapter.')}
      try{$public=Invoke-RestMethod -Uri 'https://api.ipify.org' -TimeoutSec 8 -ErrorAction Stop}catch{$issues.Add('Public IPv4 query failed.')}
      if($public -ne $Config.ExpectedVpnIPv4){$issues.Add('Observed VPNBook public IPv4 differs.')}
      if($Config.DnsProbeName -match '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$') {
        try {
          $answer=Resolve-DnsName -Name ([guid]::NewGuid().ToString('N')+'.'+$Config.DnsProbeName) -DnsOnly -NoHostsFile -ErrorAction Stop
          $dnsAnswered=($null -ne $answer)
        }catch{$issues.Add('Unique DNS query failed.')}
      } else {$issues.Add('An operator-controlled wildcard DnsProbeName is required for the lab query.')}
      $curl=Join-Path $env:SystemRoot 'System32\curl.exe'
      if(Test-Path -LiteralPath $curl){
        $null=& $curl -6 --fail --silent --max-time 5 https://api64.ipify.org
        $ipv6AttemptSucceeded=($LASTEXITCODE -eq 0)
        if($ipv6AttemptSucceeded){$issues.Add('Unexpected successful public IPv6 probe.')}
      }else{$issues.Add('IPv6 probe tool unavailable.')}
    }
    return [pscustomobject]@{Status=$(if($issues.Count){'VPNBOOK_BLOCKED'}else{'DEGRADED'});LabOnly=$true;FilterSetVerified=$true;Protected=$false
      PublicIPv4=$public;DnsAnswered=$dnsAnswered;DnsEgressVerified=$false;Ipv6ProbeSucceeded=$ipv6AttemptSucceeded;Issues=@($issues)
      Reason='These probes do not prove packet isolation; exit-side DNS, raw/forwarded traffic, boot and BFE acceptance are still required.';Native=$live}
  }
  if($RequestedMode -notin @('Arm','VPNBOOK')){throw 'Unsupported lab operation.'}
  $expectedMode=if($RequestedMode -eq 'Arm'){'ARMED_BLOCKED'}else{'VPNBOOK'}
  if($plan.Manifest.Configuration.Mode -ne $expectedMode){throw 'Requested mode and reviewed native plan differ.'}
  if($RequestedMode -eq 'VPNBOOK') {
    if(-not $state -or -not $ServerHealthPath){throw 'VPNBOOK needs an armed baseline and fresh server health artifact.'}
    $health=Get-Content -Raw -LiteralPath $ServerHealthPath | ConvertFrom-Json
    $age=[DateTimeOffset]::UtcNow-[DateTimeOffset]::Parse($health.CapturedUtc)
    if($age.TotalSeconds -lt 0 -or $age.TotalSeconds -gt 120 -or $health.Health.healthy -isnot [bool] -or -not $health.Health.healthy -or $health.Health.guard_present -isnot [bool] -or -not $health.Health.guard_present){throw 'Server health artifact is stale or blocked.'}
  }
  if($PlanOnly){return [pscustomobject]@{ChangesApplied=$false;LabOnly=$true;ProductionReady=$false;RequestedMode=$RequestedMode;NativePlan=$plan}}
  if(-not $state) {
    if($prefs.ExitNodeID -or $prefs.ExitNodeIP){throw 'Existing exit selection prevents clean lab baseline capture.'}
    if((Get-NetIPInterface -InterfaceIndex $ethernet.ifIndex -AddressFamily IPv4 -ErrorAction Stop).Dhcp -ne 'Enabled'){throw 'Lab underlay must already be DHCP managed.'}
    foreach($family in @('Tcpip','Tcpip6')) {
      $dnsSource=Get-ItemProperty -LiteralPath ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$family+'\Parameters\Interfaces\'+[string]$ethernet.InterfaceGuid) -ErrorAction Stop
      if($dnsSource.NameServer){throw 'Static underlay DNS is outside the reviewed DHCP/router-managed baseline.'}
    }
    $state=[pscustomobject]@{Version=3;Deployment=$Deployment.ToString();TunnelAdapter=[string]$ts[0].InterfaceGuid;UnderlayAdapter=[string]$ethernet.InterfaceGuid
      Dns4=@((Get-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -AddressFamily IPv4).ServerAddresses)
      Dns6=@((Get-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -AddressFamily IPv6).ServerAddresses)
      AcceptDns=[bool]$prefs.CorpDNS;AcceptRoutes=[bool]$prefs.RouteAll;Mode='CAPTURED';CapturedUtc=[DateTimeOffset]::UtcNow.ToString('o')}
    # The native helper validates the protected ProgramData directory and its
    # configuration ACLs. No new unprotected directory is created here.
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baselinePath -Encoding utf8
  }
  if($RequestedMode -eq 'VPNBOOK') {
    $current=Invoke-WalnutsBackend $Config @('verify')
    if(-not (Test-WalnutsBackendEvidence $current) -or $current.Snapshot.Manifest.Configuration.Mode -ne 'ARMED_BLOCKED'){throw 'Transition to VPNBOOK requires the verified ARMED native block.'}
    Set-LabPrefs @('set','--accept-dns=false','--accept-routes=false')
    Set-DnsClientServerAddress -InterfaceIndex $ts[0].ifIndex -ServerAddresses @('1.1.1.1','8.8.8.8')
    Set-LabPrefs @('set',('--exit-node='+$Config.ExitNodeIPv4),'--exit-node-allow-lan-access=false')
    $tailStatus=(Invoke-WalnutsLabTailscale $cli @('status','--json')) | ConvertFrom-Json
    if($tailStatus.ExitNodeStatus.TailscaleIPs -notcontains $Config.ExitNodeIPv4 -or $tailStatus.ExitNodeStatus.Online -ne $true){throw 'Requested exit is not selected/online; ARMED native block retained.'}
  }
  $null=Invoke-WalnutsBackend $Config @('arm','--disposable-vm',$Deployment.ToString())
  $live=Invoke-WalnutsBackend $Config @('verify')
  if(-not (Test-WalnutsBackendEvidence $live)){throw 'Installed native object/identity verification failed; filters retained.'}
  if($RequestedMode -eq 'Arm'){Set-LabPrefs @('set','--exit-node=')}
  $state.Mode=$expectedMode;$state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baselinePath -Encoding utf8
  return [pscustomobject]@{Status='DEGRADED';RequestedMode=$expectedMode;LabOnly=$true;FilterSetVerified=$true;Protected=$false;ProductionReady=$false;Native=$live}
}
