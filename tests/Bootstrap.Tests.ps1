Import-Module $PSScriptRoot\..\scripts\boxforming.psm1 -Force

# https://github.com/pester/Pester/wiki/Should

Add-Type -AssemblyName System.Web

$Script:Username = "forremote"
$Script:Password = [System.Web.Security.Membership]::GeneratePassword(16,4) | ConvertTo-SecureString -AsPlainText -Force

net accounts

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
      Invoke-WebRequest -Uri $LatestAnsibleWinRMScript -OutFile "ConfigureRemotingForAnsible.ps1"
      Enable-WinRM -Verbose
      1 | Should -BeExactly 1
    }

    It "Certificate for non-existing user" {
      {
        Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem" -Password $Script:Password
      } | Should -Throw
    }

    It "Should create new local user" {
      New-LocalAdminUser -Username $Script:Username -Password $Script:Password
      Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem" -Password $Script:Password
    }

    It "Should be able to start cert share web server" {
      $ServerJob = Start-Job -ScriptBlock {Start-CertShareServer -Username $Input} -InputObject $Script:Username

      $Uri = "http://localhost:50580/cert.pem"

      { Invoke-WebRequest -Uri $Uri -OutFile "cert.pem" } | Should -Not Throw

      Stop-Job $ServerJob
    }

  }

}