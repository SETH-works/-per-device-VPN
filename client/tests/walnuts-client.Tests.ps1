Describe 'Walnuts client fail-closed contract' {
  BeforeAll {
    $script = Get-Content -Raw (Join-Path $PSScriptRoot '..\walnuts-client.ps1')
  }

  It 'binds protected DNS to the detected Tailscale interface' {
    $script | Should Match 'Set-DnsClientServerAddress -InterfaceIndex \$adapter\.ifIndex -ServerAddresses'
    $script | Should Not Match 'EthernetAlias -ServerAddresses'
  }

  It 'does not automatically invoke DIRECT after a protected-mode failure' {
    $catch = ($script -split '} catch \{')[-1]
    $catch | Should Not Match 'Switch-Direct'
    $catch | Should Match 'VPNBOOK_BLOCKED'
  }

  It 'requires an explicit owner acknowledgement for DIRECT' {
    $script | Should Match 'if \(-not \$ConfirmDirect\)'
    $script | Should Match 'I UNDERSTAND THIS DISABLES VPN PROTECTION'
  }
}
