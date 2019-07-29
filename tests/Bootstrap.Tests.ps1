Import-Module $PSScriptRoot\..\scripts\boxforming.psm1 -Force

# https://github.com/pester/Pester/wiki/Should

Describe "Import-Module BoxForming" {
  Context "Certificates" {
    It "Should be able to generate certificate" {
      $Script:GeneratedCert = New-ClientAuthCert

      $Script:GeneratedCert | Should -Not -BeNullOrEmpty
    }

    It "Should be able to import certificate" {
      $CertPath = "$env:HOMEDRIVE$env:HOMEPATH\$env:USERNAME.crt.pem"
      $CertFromFile = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
      $CertFromFile.Import($CertPath)

      $CertFromFile.Thumbprint | Should -BeExactly $Script:GeneratedCert.Thumbprint

      # $Thumbprints = @(Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Thumbprint -eq $CertFromFile.Thumbprint })

      #if ($Thumbprints.Count -gt 0) {
      #  Write-Verbose "This certificate already imported"
      #}
    }

  }

  Context "WinRM" {
    It "Should be able to enable WinRM" {
      Enable-WinRM -Verbose
    }

    It "Should be able to enable WinRM with locally installed latest 'ConfigureWinRMForAnsible.ps1'" {
      $LatestAnsibleWinRMScript = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
      Invoke-WebRequest -Uri $Url -OutFile "ConfigureRemotingForAnsible.ps1"
      Enable-WinRM -Verbose
    }

    It "Should be able to install client auth certificate" {
      Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$env:USERNAME.crt.pem"
    }
  }

}