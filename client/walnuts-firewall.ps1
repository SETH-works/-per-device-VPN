# Read-only Windows Firewall audit. Dot sourcing this file performs no probes.
function Assert-WalnutsRecoveryBaseline($State, $Config, [string]$Hostname) {
  if(-not $State -or $State.Version -ne 2 -or $State.Hostname -ne $Hostname -or
     $State.EthernetAlias -ne $Config.EthernetAlias -or $State.ClientIPv4 -ne $Config.ClientTailscaleIPv4 -or
     $State.ClientIPv6 -ne $Config.ClientTailscaleIPv6 -or -not $State.TailscaleAlias -or
     $State.TailscaleIfIndex -isnot [int] -or $State.TailscaleIfIndex -lt 1 -or
     $State.OriginalAcceptDNS -isnot [bool] -or -not $State.TailscaleExe -or
     -not [IO.Path]::IsPathRooted($State.TailscaleExe)) {throw 'Missing, corrupt or mismatched recovery identity/preferences.'}
  if(@($State.OriginalProfiles).Count -ne 3 -or @($State.OriginalProfiles.Name | Sort-Object -Unique).Count -ne 3){throw 'Missing or duplicate captured profiles.'}
  foreach($p in $State.OriginalProfiles){
    if($p.Name -notin @('Domain','Private','Public') -or $p.Enabled -isnot [bool] -or
       [string]$p.DefaultOutboundAction -notin @('Allow','Block','NotConfigured')){throw 'Invalid captured firewall profile values.'}
  }
  foreach($field in @('OriginalTailscaleDnsIPv4','OriginalTailscaleDnsIPv6')) {
    if($State.PSObject.Properties.Name -notcontains $field){throw 'Captured DNS baseline is incomplete.'}
    foreach($value in $State.$field){
      $ip=$null
      if(-not [Net.IPAddress]::TryParse([string]$value,[ref]$ip)){throw 'Invalid captured DNS address.'}
    }
  }
}

function Get-WalnutsServiceIdentity($Service) {
  # SCM's quoted executable is authoritative; the adjacent CLI is not transport.
  $match = [regex]::Match([string]$Service.PathName, '^"([^"\r\n]+\.exe)"(?:\s|$)|^([^\s"]+\.exe)(?:\s|$)', 'IgnoreCase')
  if (-not $match.Success) { throw 'Ambiguous or missing Tailscale service executable' }
  $path = $match.Groups[1].Value
  if (-not $path) { $path = $match.Groups[2].Value }
  if (-not [IO.Path]::IsPathRooted($path)) { throw 'Tailscale service path must be absolute' }
  [pscustomobject]@{Name=[string]$Service.Name; Program=$path; State=[string]$Service.State; ProcessId=$Service.ProcessId}
}

function Get-WalnutsFirewallSnapshot {
  $errors = [Collections.Generic.List[string]]::new()
  $rows = @()
  try {
    $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -TracePolicyStore -ErrorAction Stop)
    foreach ($r in $rules) {
      try {
        $app = @($r | Get-NetFirewallApplicationFilter -ErrorAction Stop)
        $svc = @($r | Get-NetFirewallServiceFilter -ErrorAction Stop)
        $port = @($r | Get-NetFirewallPortFilter -ErrorAction Stop)
        $address = @($r | Get-NetFirewallAddressFilter -ErrorAction Stop)
        $iface = @($r | Get-NetFirewallInterfaceFilter -ErrorAction Stop)
        $type = @($r | Get-NetFirewallInterfaceTypeFilter -ErrorAction Stop)
        if ($app.Count -ne 1 -or $svc.Count -ne 1 -or $port.Count -ne 1 -or $address.Count -ne 1 -or $iface.Count -ne 1 -or $type.Count -ne 1) { throw 'Non-singleton associated filter' }
        $rows += [pscustomobject]@{
          Name=$r.Name; DisplayName=$r.DisplayName; Group=$r.Group; Enabled=[string]$r.Enabled
          Action=[string]$r.Action; Direction=[string]$r.Direction; Profile=@([string]$r.Profile -split ',\s*')
          Program=$app[0].Program; Package=$app[0].Package; Service=$svc[0].Service
          Protocol=[string]$port[0].Protocol; LocalPort=@($port[0].LocalPort); RemotePort=@($port[0].RemotePort)
          LocalAddress=@($address[0].LocalAddress); RemoteAddress=@($address[0].RemoteAddress)
          InterfaceAlias=@($iface[0].InterfaceAlias); InterfaceType=@($type[0].InterfaceType)
          PolicyStoreSource=$r.PolicyStoreSource; PolicyStoreSourceType=[string]$r.PolicyStoreSourceType
          PrimaryStatus=[string]$r.PrimaryStatus; EnforcementStatus=@($r.EnforcementStatus | ForEach-Object { [string]$_ })
          FilterError=$null
        }
      } catch {
        $rows += [pscustomobject]@{Name=$r.Name; Enabled=[string]$r.Enabled; Direction=[string]$r.Direction; Action=[string]$r.Action; FilterError=$_.Exception.Message}
      }
    }
  } catch { $errors.Add('ActiveStore rules: '+$_.Exception.Message) }
  $profiles=@(); $adapters=@(); $connections=@(); $service=$null
  try {$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)} catch {$errors.Add('Profiles: '+$_.Exception.Message)}
  try {$adapters=@(Get-NetAdapter -ErrorAction Stop); $connections=@(Get-NetConnectionProfile -ErrorAction Stop)} catch {$errors.Add('Interfaces: '+$_.Exception.Message)}
  try {$service=Get-WalnutsServiceIdentity (Get-CimInstance Win32_Service -Filter "Name='Tailscale'" -ErrorAction Stop)} catch {$errors.Add('Service: '+$_.Exception.Message)}
  [pscustomobject]@{Rules=$rows; Profiles=$profiles; Adapters=$adapters; Connections=$connections; Service=$service; Errors=@($errors)}
}

function Get-WalnutsAddressScope([object[]]$Addresses) {
  if (-not $Addresses.Count) { return 'Unknown' }
  $public=$false
  foreach ($value in $Addresses) {
    # Only explicitly local ranges are proven restricted. Keywords such as
    # LocalSubnet, Internet, DNS and dynamic keywords need runtime expansion.
    $text=[string]$value
    if ($text -in @('Any','*','Internet','0.0.0.0/0','::/0')) {$public=$true; continue}
    if ($text -in @('127.0.0.0/8','::1','fe80::/10','169.254.0.0/16','224.0.0.0/24','ff02::/16','255.255.255.255')) {continue}
    $ip=$null
    if (-not [Net.IPAddress]::TryParse($text,[ref]$ip)) {return 'Unknown'}
    if ($ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
      if (-not ($ip.IsIPv6LinkLocal -or $ip.Equals([Net.IPAddress]::IPv6Loopback))) {$public=$true}
    } else {
      $b=$ip.GetAddressBytes()
      if (-not ($b[0] -eq 127 -or ($b[0] -eq 169 -and $b[1] -eq 254) -or ($b[0] -eq 224 -and $b[1] -eq 0 -and $b[2] -eq 0) -or $text -eq '255.255.255.255')) {$public=$true}
    }
  }
  if($public){return 'PublicPossible'}
  return 'LocalOnly'
}

function Get-WalnutsRuleAssessment($Rule, [string]$EthernetAlias, [string]$ServiceProgram) {
  $category='PotentialBypass'; $reason='Effective scope could not be established; review required.'
  if ($Rule.Enabled -eq 'False' -or $Rule.Direction -eq 'Inbound') {
    $category='Restricted'; $reason='Disabled or inbound rule cannot authorize outbound Ethernet traffic.'
  } elseif ($Rule.FilterError) {
    $reason='Associated filter query failed: '+$Rule.FilterError
  } elseif ($Rule.Enabled -ne 'True' -or $Rule.Direction -ne 'Outbound') {
    $reason='Unknown enabled state or direction.'
  } elseif ($Rule.PrimaryStatus -ne 'OK' -or -not @($Rule.EnforcementStatus).Count -or
            @($Rule.EnforcementStatus | Where-Object {$_ -notin @('Full','NotApplicable')}).Count) {
    $reason='Effective policy enforcement state is missing or not fully resolved.'
  } elseif (-not @($Rule.InterfaceAlias).Count -or -not @($Rule.InterfaceType).Count -or -not @($Rule.Profile).Count -or -not $Rule.Program -or -not $Rule.Service -or -not $Rule.Protocol -or -not @($Rule.LocalAddress).Count -or -not @($Rule.LocalPort).Count -or -not @($Rule.RemotePort).Count) {
    $reason='One or more required effective filters are missing.'
  } elseif (@($Rule.InterfaceAlias | Where-Object {$_ -eq 'Any' -or $_ -eq '*' -or $EthernetAlias -like $_}).Count -eq 0) {
    $category='Restricted'; $reason='Interface alias excludes the protected Ethernet adapter; other interfaces are unchanged.'
  } elseif (@($Rule.InterfaceType | Where-Object {$_ -in @('Any','Wired')}).Count -eq 0) {
    if(@($Rule.InterfaceType | Where-Object {$_ -notin @('Wireless','RemoteAccess')}).Count -eq 0) {
      $category='Restricted'; $reason='Interface type excludes wired Ethernet.'
    }
  } elseif ($Rule.Action -eq 'Block') {
    $category='PotentialBypass'; $reason='Explicit block may prevent Tailscale/DHCP even in the presence of an allow. It is not proof of complete isolation.'
  } elseif ($Rule.Action -ne 'Allow') {
    $reason='Unknown firewall action.'
  } else {
    $scope=Get-WalnutsAddressScope @($Rule.RemoteAddress)
    if($scope -eq 'LocalOnly') {
      $category='Restricted'; $reason='Remote addresses are explicitly link-local, loopback, or local multicast; no public destination is authorized by this rule.'
    } elseif($scope -eq 'Unknown') {
      $reason='Remote address keyword, range or prefix requires expansion; cannot prove Ethernet exclusion.'
    } elseif($Rule.Program -eq $ServiceProgram -and $ServiceProgram -and $Rule.Service -eq 'Tailscale' -and
             @($Rule.InterfaceAlias).Count -eq 1 -and $Rule.InterfaceAlias[0] -eq $EthernetAlias -and
             @($Rule.Profile).Count -eq 1 -and $Rule.Profile[0] -eq 'Any' -and
             $Rule.Protocol -in @('TCP','6','UDP','17') -and
             @($Rule.RemotePort).Count -eq 1 -and
             (($Rule.Protocol -in @('TCP','6') -and $Rule.RemotePort[0] -eq '443') -or ($Rule.Protocol -in @('UDP','17') -and $Rule.RemotePort[0] -eq 'Any')) -and
             @($Rule.LocalPort).Count -eq 1 -and $Rule.LocalPort[0] -eq 'Any' -and
             @($Rule.LocalAddress).Count -eq 1 -and $Rule.LocalAddress[0] -eq 'Any' -and
             $Rule.PrimaryStatus -eq 'OK' -and $Rule.EnforcementStatus -contains 'Full' -and $Rule.PolicyStoreSourceType -eq 'Local') {
      $category='ApprovedUnderlayException'; $reason='Candidate envelope matches SCM service path plus Tailscale service, Ethernet, and UDP roaming or TCP/443 DERP/control. Runtime service attribution and signature still require verification; this is not enforcement proof.'
    } else {
      $category='ConfirmedBypassRisk'; $reason='Enabled explicit outbound allow can match Ethernet and a public destination. Program/service/ports constrain who can bypass, not whether default Block overrides it. Other blocks and routing may still prevent a packet.'
    }
  }
  [pscustomobject]@{Name=$Rule.Name; Category=$category; Reason=$reason; Filters=$Rule}
}

function Get-WalnutsEgressAudit($Snapshot, [string]$EthernetAlias) {
  $issues=[Collections.Generic.List[string]]::new()
  foreach($errorText in $Snapshot.Errors){$issues.Add($errorText)}
  $ethernet=@($Snapshot.Adapters | Where-Object Name -eq $EthernetAlias)
  if($ethernet.Count -ne 1 -or $ethernet[0].Status -ne 'Up'){$issues.Add('Reviewed Ethernet adapter is absent, ambiguous or down.')}
  if(-not $Snapshot.Service -or $Snapshot.Service.State -ne 'Running'){$issues.Add('Tailscale service identity/running state unavailable.')}
  $profiles=@($Snapshot.Profiles)
  if($profiles.Count -ne 3){$issues.Add('All three effective firewall profiles were not captured.')}
  foreach($p in $profiles){
    if([string]$p.Enabled -ne 'True' -or [string]$p.DefaultOutboundAction -ne 'Block'){$issues.Add("$($p.Name): effective firewall is not enabled/outbound Block.")}
    if([string]$p.AllowLocalFirewallRules -ne 'True'){$issues.Add("$($p.Name): local rule merge is disabled or unknown; managed policy review required.")}
  }
  $rows=@(foreach($rule in $Snapshot.Rules){Get-WalnutsRuleAssessment $rule $EthernetAlias $Snapshot.Service.Program})
  $counts=[ordered]@{}
  foreach($category in @('ConfirmedBypassRisk','PotentialBypass','Restricted','ApprovedUnderlayException')){$counts[$category]=@($rows | Where-Object Category -eq $category).Count}
  if($counts['ConfirmedBypassRisk']){$issues.Add('Explicit allows can match public Ethernet destinations; an independent boundary is required.')}
  if($counts['PotentialBypass']){$issues.Add('Unresolved scopes or explicit-block transport conflicts require review.')}
  [pscustomobject]@{
    Ready=$false; Protected=$false; Enforcement='UNAVAILABLE'; CapturedUtc=[DateTime]::UtcNow.ToString('o')
    Blockers=@('No validated independent underlay enforcement backend is installed. Arm and VPNBOOK are disabled.')+@($issues)
    Counts=$counts; Rules=$rows; Service=$Snapshot.Service; Profiles=$profiles; Adapters=$Snapshot.Adapters
    Connections=$Snapshot.Connections; HyperV='Not modified; forwarded VM traffic and WFP layers require separate lab verification.'
    PlannedDns=[pscustomobject]@{Interface='Detected Tailscale interface';IPv4=@('1.1.1.1','8.8.8.8');AcceptTailscaleDns=$false;Ethernet='DHCP; unchanged during protection';EnforcementVerified=$false}
  }
}
