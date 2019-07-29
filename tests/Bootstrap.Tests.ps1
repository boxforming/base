Import-Module $PSScriptRoot\..\scripts\boxforming.psm1 -Force

# https://github.com/pester/Pester/wiki/Should

$Script:Password = -join ((48..57) *120 | Get-Random -Count 10 | % {[char]$_})
$Script:Username = "forremote"

Describe "Import-Module BoxForming" {
  Context "Certificates" {
    It "Should be able to generate certificate" {
      $Script:GeneratedCert = New-ClientAuthCert -Username $Script:Username

      $Script:GeneratedCert | Should -Not -BeNullOrEmpty
    }

    It "Should be able to import certificate" {
      $CertPath = "$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem"
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
      Write-Output (Get-Service WinRM).Status
      Enable-WinRM -Verbose
      Write-Output (Get-Service WinRM).Status
      1 | Should -BeExactly 1
    }

    It "Should be able to enable WinRM with locally installed latest 'ConfigureWinRMForAnsible.ps1'" {
      $LatestAnsibleWinRMScript = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
      Invoke-WebRequest -Uri $Url -OutFile "ConfigureRemotingForAnsible.ps1"
      Enable-WinRM -Verbose
      1 | Should -BeExactly 1
    }

    It "Certificate for non-existing user" {
      Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem" -Password $Script:Password
    }

    It "Should create new local user" {
      New-LocalAdminUser -Username $Script:Username -Password $Script:Password
      Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem" -Password $Script:Password
    }

  }

}