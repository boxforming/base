Import-Module $PSScriptRoot\..\scripts\access-controller.psm1 -Force

# https://github.com/pester/Pester/wiki/Should

Add-Type -AssemblyName System.Web

BeforeAll {
  $Username = "forremote"
  $Password = [System.Web.Security.Membership]::GeneratePassword(16,4) | ConvertTo-SecureString -AsPlainText -Force
  $GeneratedCert = New-ClientAuthCert -Username $Username
}

Describe "Import-Module BoxFormingAccessController" {
  Context "Certificates" {
    It "Should be able to generate certificate" {
      $GeneratedTCert = New-ClientAuthCert -Username "test"

      $GeneratedTCert | Should -Not -BeNullOrEmpty
    }

    It "Should be able to import certificate" {
      $CertPath = "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem"
      $CertFromFile = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
      $CertFromFile.Import($CertPath)

      $CertFromFile.Thumbprint | Should -BeExactly $GeneratedCert.Thumbprint

      # $Thumbprints = @(Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Thumbprint -eq $CertFromFile.Thumbprint })

      #if ($Thumbprints.Count -gt 0) {
      #  Write-Verbose "This certificate already imported"
      #}
    }

  }

  Context "Creating a new admin user" {

    It "Should create new local user" {
      {
        New-RemoteAdminUser -Username $Username -Password $Password
      } | Should -Not -Throw
    }

    It "Should be able to import certificate" {
      {
        Import-ClientAuthCert -File "$env:HOMEDRIVE$env:HOMEPATH\$Username.crt.pem" -Password $Password
      } | Should -Not -Throw
    }
  }

  #Context "Importing certificate" {


      #{
      #  Import-ClientAuthCert -Url $Uri -Password $Script:Password
      #} | Should -Throw "The WS-Management service cannot create the resource because it already exists"

  #}

}

