Import-Module $PSScriptRoot\..\scripts\boxforming -Force

Describe "Import-Module BoxForming" {
  Context "Module Exports" {
    It "Should export at least one function" {
      @(Get-Command -Module BoxForming).Count | Should BeGreaterThan 0
    }
  }
}