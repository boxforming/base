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

  Context "PS Web Server" {

    It "Should be able to start cert share web server" {

      $Root = $PSScriptRoot

      $InitScript = [scriptblock]::Create("Import-Module '$Root\..\scripts\access-controller.psm1' -ArgumentList True -Force")

      $ServerJob = Start-Job -InitializationScript $InitScript -ScriptBlock {
        Start-CertShareServer -Port 50580 -Username $Input
      } -InputObject $Script:Username

      Start-Sleep 1.0

      # Write-Host $ServerJob.State

      If ($ServerJob.State -ne "Running") {
        # $ServerJob | Format-Table | Write-Host
        Write-Host (Receive-Job $ServerJob) -ForegroundColor Green
      }

      $ServerJob.State | Should -Be "Running"

      $Uri = "http://localhost:50580/cert.pem"

      {
        Invoke-WebRequest -Uri $Uri -UseBasicParsing
      } | Should -Not -Throw

      $CertWebBytes = (Invoke-WebRequest -Uri $Uri -UseBasicParsing).Content

      $CertWebContents = [System.Text.Encoding]::ASCII.GetString($CertWebBytes)

      # $bytes = [System.IO.File]::ReadAllBytes("path_to_the_file")
      $CertFileContents = [System.IO.File]::ReadAllText("$env:HOMEDRIVE$env:HOMEPATH\$Script:Username.crt.pem")

      $CertWebContents | Should -Be $CertFileContents

      #{
      #  Import-ClientAuthCert -Url $Uri -Password $Script:Password
      #} | Should -Throw "The WS-Management service cannot create the resource because it already exists"

      Stop-Job $ServerJob

    }

  }

}
