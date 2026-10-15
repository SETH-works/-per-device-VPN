[CmdletBinding()]
param([string]$Configuration='Release')
$ErrorActionPreference='Stop'
$env:DOTNET_CLI_TELEMETRY_OPTOUT='1'
$env:DOTNET_SKIP_FIRST_TIME_EXPERIENCE='1'
dotnet build "$PSScriptRoot\Walnuts.Wfp.csproj" -c $Configuration --nologo -p:UseSharedCompilation=false
if($LASTEXITCODE -ne 0){throw 'Native helper build failed.'}
$output=Join-Path $PSScriptRoot "bin\$Configuration\net11.0"
& (Join-Path $output 'Walnuts.Wfp.exe') self-test
if($LASTEXITCODE -ne 0){throw 'Offline helper tests failed.'}
$files=@(foreach($name in @('Walnuts.Wfp.exe','Walnuts.Wfp.dll','Walnuts.Wfp.deps.json','Walnuts.Wfp.runtimeconfig.json')){
  [pscustomobject]@{File=$name;SHA256=(Get-FileHash -LiteralPath (Join-Path $output $name) -Algorithm SHA256).Hash}
})
$files | ConvertTo-Json
