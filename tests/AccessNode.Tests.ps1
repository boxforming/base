Import-Module $PSScriptRoot\..\scripts\access-node.psm1 -Force

# https://github.com/pester/Pester/wiki/Should

Add-Type -AssemblyName System.Web

BeforeAll {
  $Username = "forremote"
  $Password = [System.Web.Security.Membership]::GeneratePassword(16,4) | ConvertTo-SecureString -AsPlainText -Force
  $GeneratedCert = New-ClientAuthCert -Username $Username
}

Describe "Import-Module BoxFormingAccessNode" {
  Context "Certificates" {

    It "Should be able to import certificate" {
      {
        $CertPath = "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem"
        $CertFromFile = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
        $CertFromFile.Import($CertPath)
      } | Should -Not -Throw

      $CertFromFile.Thumbprint | Should -BeExactly $GeneratedCert.Thumbprint

    }

    It "Should be able to generate certificate" {
      $GeneratedTCert = New-ClientAuthCert -Username "test"

      $GeneratedTCert | Should -Not -BeNullOrEmpty
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

    It "Certificate for non-existing user should throw" {
      {
        Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem" -Password $Password
      } | Should -Throw
    }

    It "Should create new local user" {
      New-RemoteAdminUser -Username $Username -Password $Password
      Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem" -Password $Password
    }

    It "Should be able to import certificate" {
      {
        Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem" -Password $Password
      } | Should -Not -Throw
    }

  }

}

