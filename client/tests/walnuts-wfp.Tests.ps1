. (Join-Path $PSScriptRoot '..\walnuts-wfp.ps1')
Describe 'Controller verifies native evidence rather than process launch' {
  It 'rejects absent native evidence' {Test-WalnutsBackendEvidence $null | Should Be $false}
  It 'rejects process launch alone' {Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;Success=$true}) | Should Be $false}
  It 'rejects text booleans from an unexpected protocol' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;FilterSetVerified='True';IdentityVerified='True';Snapshot=[pscustomobject]@{Manifest=@{}}}) | Should Be $false
  }
  It 'rejects missing installed filters despite a valid identity' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;FilterSetVerified=$false;IdentityVerified=$true;Snapshot=[pscustomobject]@{Manifest=@{}}}) | Should Be $false
  }
  It 'rejects stale adapter or service identity despite existing filters' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;FilterSetVerified=$true;IdentityVerified=$false;Snapshot=[pscustomobject]@{Manifest=@{}}}) | Should Be $false
  }
  It 'rejects a mismatched protocol version' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=2;FilterSetVerified=$true;IdentityVerified=$true;Snapshot=[pscustomobject]@{Manifest=@{}}}) | Should Be $false
  }
  It 'rejects a stale journal without engine metadata' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;FilterSetVerified=$true;IdentityVerified=$true;Snapshot=$null}) | Should Be $false
  }
  It 'accepts verified engine structure only as lab configuration evidence' {
    $data=[pscustomobject]@{Schema=1;FilterSetVerified=$true;IdentityVerified=$true;IntentMatches=$true;Snapshot=[pscustomobject]@{Manifest=@{Deployment='lab'}};Protected=$false}
    Test-WalnutsBackendEvidence $data | Should Be $true
    $data.Protected | Should Be $false
  }
  It 'rejects mismatched intent even with live filters and matching identity' {
    Test-WalnutsBackendEvidence ([pscustomobject]@{Schema=1;FilterSetVerified=$true;IdentityVerified=$true;IntentMatches=$false;Snapshot=[pscustomobject]@{Manifest=@{Deployment='lab'}}}) | Should Be $false
  }
}
