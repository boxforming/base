Import-Module $PSScriptRoot\..\scripts\sysinfo.ps1 -Force

Describe "Import-Module Sysinfo" {
  Context "Module Exports" {
    It "Should export at least one function" {
      @(Get-Command -Module Sysinfo).Count | Should -BeGreaterThan 0
    }
  }
}

Describe "Sysinfo data" {
  #Context "" {
    It "Should be not empty" {
      $SysInfo = Get-Sysinfo

      $StringSysInfo = $SysInfo.psobject.properties|%{$_.Name + "=" + $SysInfo.($_.Name)}
      Write-Host $StringSysInfo
      Write-Host $SysInfo

      $SysInfo.psobject.properties['hostname'] | Should -Not -BeNullOrEmpty
    }
  #}
}