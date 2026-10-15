#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][switch]$DisposableVm,
      [Parameter(Mandatory=$true)][string]$ExpectedHostname,
      [Parameter(Mandatory=$true)][ValidateSet('CaptureStart','CaptureStop','Probe','Stream')][string]$Stage,
      [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
      [string]$SourceIPv4,[string]$ReceiverIPv4,[string]$ReceiverIPv6,
      [ValidateRange(1,65535)][int]$ReceiverPort=8443,
      [string]$DnsProbeName,[string]$DohUrl)
$ErrorActionPreference='Stop'
if(-not $DisposableVm -or $env:COMPUTERNAME -eq 'STREAM' -or $env:COMPUTERNAME -ne $ExpectedHostname){throw 'Only the explicitly named disposable VM is allowed.'}
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine|VirtualBox|VMware|KVM|QEMU'){throw 'Existing disposable VM required.'}
if(-not $PSCmdlet.ShouldProcess($ExpectedHostname,"Run isolated packet-test stage $Stage; no automatic firewall/DNS/service changes")){return}
New-Item -ItemType Directory -Force -Path $EvidenceDirectory | Out-Null
$id=[guid]::NewGuid().ToString('N')
if($Stage -eq 'CaptureStart') {
  # Existing captures/filters must be inspected first. This does not reset them.
  & pktmon status
  & pktmon start --capture --comp nics --pkt-size 0 --file-size 64 --file-name (Join-Path $EvidenceDirectory 'packets.etl')
  if($LASTEXITCODE -ne 0){throw 'Capture start failed. Do not stop someone else''s existing capture.'}
  return
}
if($Stage -eq 'CaptureStop') {
  & pktmon counters | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'counters.txt')
  & pktmon stop
  if($LASTEXITCODE -ne 0){throw 'Capture stop failed.'}
  & pktmon etl2pcap (Join-Path $EvidenceDirectory 'packets.etl') --out (Join-Path $EvidenceDirectory 'packets.pcapng')
  return
}
if(-not $SourceIPv4 -or -not $ReceiverIPv4){throw 'An explicitly reviewed source and independent controlled receiver are required.'}
$source=[Net.IPAddress]::Parse($SourceIPv4)
$peer=[Net.IPAddress]::Parse($ReceiverIPv4)
if($source.AddressFamily -ne 'InterNetwork' -or $peer.AddressFamily -ne 'InterNetwork'){throw 'IPv4 endpoints required.'}
$results=[Collections.Generic.List[object]]::new()
function Record([string]$Name,[scriptblock]$Action) {
  $start=[DateTimeOffset]::UtcNow.ToString('o')
  try{$value=& $Action; $results.Add([pscustomobject]@{Test=$Name;Timestamp=$start;ClientResult='Completed';Detail=$value;PacketVerdict='UNVERIFIED'})}
  catch{$results.Add([pscustomobject]@{Test=$Name;Timestamp=$start;ClientResult='Failed';Detail=$_.Exception.Message;PacketVerdict='UNVERIFIED'})}
}
function New-BoundTcp {
  return [Net.Sockets.TcpClient]::new([Net.IPEndPoint]::new($source,0))
}
Record 'physical-source IPv4 TCP' {
  $tcp=New-BoundTcp
  try {
    $pending=$tcp.ConnectAsync($peer,$ReceiverPort)
    if(-not $pending.Wait(5000)){throw 'TCP connect timeout'}
    $stream=$tcp.GetStream()
    $count=if($Stage -eq 'Stream'){120}else{1}
    for($i=0;$i -lt $count;$i++){
      $payload=[Text.Encoding]::ASCII.GetBytes("WALNUTS-$id-$i`n")
      $stream.Write($payload,0,$payload.Length)
      if($count -gt 1){Start-Sleep -Milliseconds 500}
    }
    'Application wrote tagged data; independent receiver/capture must establish delivery.'
  } finally{$tcp.Dispose()}
}
if($Stage -eq 'Probe') {
  if($DnsProbeName) {
    Record 'physical-source DNS UDP 53' {
      $udp=[Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($source,0))
      try {
        $label=$id+'.'+$DnsProbeName.TrimEnd('.')
        $query=[Collections.Generic.List[byte]]::new()
        $query.AddRange([byte[]]@(1,2,1,0,0,1,0,0,0,0,0,0))
        foreach($part in $label.Split('.')){if($part.Length -gt 63){throw 'Invalid DNS label'};$query.Add([byte]$part.Length);$query.AddRange([Text.Encoding]::ASCII.GetBytes($part))}
        $query.AddRange([byte[]]@(0,0,1,0,1))
        $bytes=$query.ToArray();$null=$udp.Send($bytes,$bytes.Length,[Net.IPEndPoint]::new($peer,53))
        'UDP send returned; it does not establish whether a packet escaped.'
      } finally{$udp.Dispose()}
    }
    Record 'Windows DNS Client unique name' {Resolve-DnsName -Name ($id+'.'+$DnsProbeName) -DnsOnly -NoHostsFile -ErrorAction Stop | Out-String}
  }
  if($DohUrl){
    Record 'application HTTPS/DoH URL' {
      $uri=[uri]$DohUrl
      if($uri.Scheme -ne 'https'){throw 'An operator-controlled HTTPS DNS endpoint is required.'}
      Invoke-WebRequest -Uri $uri.AbsoluteUri -TimeoutSec 5 -UseBasicParsing | Select-Object StatusCode
    }
  }
  if($ReceiverIPv6){
    Record 'native IPv6 TCP' {
      $tcp=[Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetworkV6)
      try{if(-not $tcp.ConnectAsync([Net.IPAddress]::Parse($ReceiverIPv6),$ReceiverPort).Wait(5000)){throw 'IPv6 timeout'};'Connected'}finally{$tcp.Dispose()}
    }
  }
  Record 'raw protocol 41 (external capture required)' {
    $socket=[Net.Sockets.Socket]::new([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]41)
    try {
      $socket.Bind([Net.IPEndPoint]::new($source,0))
      $payload=[byte[]]::new(40);$payload[0]=0x60;$payload[6]=59;$payload[7]=1
      $null=$socket.SendTo($payload,[Net.IPEndPoint]::new($peer,0))
      'Raw send returned; an independent receiver must check protocol 41.'
    } finally{$socket.Dispose()}
  }
}
$results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $EvidenceDirectory ($Stage+'-'+$id+'.json')) -Encoding utf8
$results | ConvertTo-Json -Depth 8
# No row can be PASS from a client timeout. Packet evidence is reviewed later.
