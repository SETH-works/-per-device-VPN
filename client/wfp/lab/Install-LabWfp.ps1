#requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess=$true,ConfirmImpact='High')]
param([Parameter(Mandatory=$true)][switch]$DisposableVm,
      [Parameter(Mandatory=$true)][string]$ExpectedHostname,
      [Parameter(Mandatory=$true)][string]$ReviewedConfiguration,
      [string]$BuildDirectory="$PSScriptRoot\..\bin\Release\net11.0")
$ErrorActionPreference='Stop'
if(-not $DisposableVm -or $env:COMPUTERNAME -eq 'STREAM' -or $env:COMPUTERNAME -ne $ExpectedHostname){throw 'Only the explicitly named disposable VM is allowed.'}
if((Get-CimInstance Win32_ComputerSystem).Model -notmatch 'Virtual Machine|VirtualBox|VMware|KVM|QEMU'){throw 'Existing VM required; this script never creates a VM.'}
$config=Get-Content -Raw -LiteralPath $ReviewedConfiguration | ConvertFrom-Json
if($config.Hostname -ne $ExpectedHostname -or [guid]$config.Deployment -eq [guid]::Empty -or $config.Mode -ne 'ARMED_BLOCKED'){throw 'Review a fresh ARMED lab configuration first.'}
if(Get-Service WalnutsWfpGuard -ErrorAction SilentlyContinue){throw 'Existing guard service: use inspected recovery, not replacement.'}
$binaryRoot=Join-Path $env:ProgramFiles 'WalnutsWfp'
$stateRoot=Join-Path $env:ProgramData 'WalnutsWfp'
if((Test-Path $binaryRoot) -or (Test-Path $stateRoot)){throw 'Existing staging directories require ownership review before installation.'}
if(-not $PSCmdlet.ShouldProcess($ExpectedHostname,'Install the lab-only WFP guard files and automatic service (does not arm filters)')){return}
foreach($directory in @($binaryRoot,$stateRoot)) {
  New-Item -ItemType Directory -Path $directory | Out-Null
  $acl=[Security.AccessControl.DirectorySecurity]::new()
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  $acl.SetAccessRuleProtection($true,$false)
  foreach($sid in @('S-1-5-18','S-1-5-32-544')){
    $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new($sid),'FullControl','ContainerInherit,ObjectInherit','None','Allow'))
  }
  Set-Acl -LiteralPath $directory -AclObject $acl
}
foreach($name in @('Walnuts.Wfp.exe','Walnuts.Wfp.dll','Walnuts.Wfp.deps.json','Walnuts.Wfp.runtimeconfig.json')){
  Copy-Item -LiteralPath (Join-Path $BuildDirectory $name) -Destination (Join-Path $binaryRoot $name)
}
Copy-Item -LiteralPath $ReviewedConfiguration -Destination (Join-Path $stateRoot 'lab.json')
foreach($file in @(Get-ChildItem -LiteralPath $binaryRoot -File)+(Get-Item -LiteralPath (Join-Path $stateRoot 'lab.json'))){
  $acl=Get-Acl -LiteralPath $file.FullName
  $acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))
  Set-Acl -LiteralPath $file.FullName -AclObject $acl
}
$image='"'+(Join-Path $binaryRoot 'Walnuts.Wfp.exe')+'" service'
New-Service -Name WalnutsWfpGuard -BinaryPathName $image -StartupType Automatic -DependsOn BFE -DisplayName 'Walnuts WFP disposable lab guard' | Out-Null
Start-Service WalnutsWfpGuard
Write-Output 'Lab files/service installed. Filters are NOT armed. Capture plan and baseline before the separate arm operation.'
