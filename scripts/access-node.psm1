#  . { iwr -useb http://apla.me/__2.ps1 } | iex
#  . { gc -Raw .\boxforming.ps1 } | iex
# Start-Process powershell "-NoProfile -NoExit -Command `" . { iwr -useb http://apla.me/__2.ps1 } | iex `"" -Verb RunAs

#[CmdletBinding()]
#Param()

# Get the ID and security principal of the current user account
$myWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($myWindowsID)

# Get the security principal for the Administrator role
$adminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator

# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole)) {
	Write-Verbose "Elevated prompt, proceeding"
} else {
	Write-Error "This script should be run with elevated privileges"
}

# https://github.com/PowerShell/Win32-OpenSSH/releases


New-Module -Name BoxFormingAccessNode -ScriptBlock {
	param(
	[parameter(Position=0,Mandatory=$false)]
	[boolean] $BeQuiet = $false
	)
	# $BoxForming = New-Module -Name BoxFormingClosure  -ScriptBlock {
	
	# Support for -Verbose option
	
	
	$ErrorActionPreference = "Stop"
	
	$LatestAnsibleWinRMScript = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
	$BinnedAnsibleWinRMScript = "https://raw.githubusercontent.com/ansible/ansible/24b46334817b408a4ad1c328d6b1641b6a9bec12/examples/scripts/ConfigureRemotingForAnsible.ps1";
	
	# Write-Host "PSScriptRoot '$($PSScriptRoot)'"
	
	# iex(gc ".\ConfigureRemotingForAnsible.ps1" -raw)
	if (Test-Path -Path ".\ConfigureRemotingForAnsible.ps1") {
		Write-Verbose "Using local script to configure WinRM"
		$AnsibleRes = Get-Content ".\ConfigureRemotingForAnsible.ps1" -Raw
	} else {
		Write-Verbose "Loading script to configure WinRM"
		$AnsibleRes = Invoke-WebRequest -UseBasicParsing $BinnedAnsibleWinRMScript
	}
	
	Function Enable-WinRM {
		Param(
		[parameter(ValueFromRemainingArguments = $true)]
		[string[]]$Passthrough
		)
		
		Invoke-Expression (
		"Function Configure-WinRMAnsible {`r`n" +
		"$($AnsibleRes)`r`n" +
		"Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value `$true`r`n" +
		"}"
		)
		
		Configure-WinRMAnsible @Passthrough
	}
	
	# Function Install-WinRM {
	
	# 	$AnsibleWinRMScript = "https://raw.githubusercontent.com/ansible/ansible/devel/examples/scripts/ConfigureRemotingForAnsible.ps1"
	
	# 	. { iwr -useb $AnsibleWinRMScript } | iex
	
	# 	Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true
	# }
	
	
	Function Add-Cert {
		Param (
		[Security.Cryptography.X509Certificates.StoreName]$StoreName,
		[Security.Cryptography.X509Certificates.X509Certificate]$Cert
		)
		
		$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
		$Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName, $StoreLocation
		$Store.Open("MaxAllowed")
		$Store.Add($Cert)
		$Store.Close()
		
	}
	
	Function Remove-Cert {
		Param (
		[Security.Cryptography.X509Certificates.StoreName]$StoreName,
		[Security.Cryptography.X509Certificates.X509Certificate]$Cert
		)
		
		$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
		$Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName, $StoreLocation
		$Store.Open("MaxAllowed")
		
		$Store.Remove($Cert)
		$Store.Close()
		
	}
	
	
	Function Import-ClientAuthCert {
		[CmdletBinding()]
		Param (
		[string] $File = "$env:HOMEDRIVE$env:HOMEPATH\crt.pem",
		[string] $Url,
		[SecureString] $Password
		)
		
		if ($Url) {
			$startTime = Get-Date
			
			Invoke-WebRequest $Url -UseBasicParsing -OutFile $File
			# Write-Verbose "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
		}
		
		# here issuing certificate == pubkey
		$Cert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2
		
		try {
			$Cert.Import($File)
			Write-Verbose "Certificate loaded: Subject $($Cert.Subject) Issuer $($Cert.Issuer) Thumbprint $($Cert.Thumbprint)"
		} catch {
			Write-Error "Cannot load certificate from $File"
			Write-Error $_.Exception.Message
			break
		}
		
		#if ([string]::IsNullOrWhiteSpace($Username)) {
		#	$Username = $env:UserName
		#}
		
		#region user check

		# remove CN= from cert subject
		$CertUsername = ($Cert.Subject).Substring(3)

				# WinRM doesn't allow to add certificate for non-local users:
		# The WINRM certificate mapping configuration operation cannot be completed because the user credentials
		# could not be verified.  Please check the username and password used for mapping this certificate and verify that it is
		# a non-domain account and try again.
		# New-Item -Path WSMan:\localhost\ClientCertificate `
		
		# Get-LocalUser not available on Windows 8.1
		# $HaveCertUser = Get-LocalUser -Name $CertUsername -ErrorAction SilentlyContinue
		$HaveCertUser = @(Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$($CertUsername)'").Count
		
		if (!$HaveCertUser) {
			$Username = ($Cert.Subject).Substring(3)
			Write-Error "Cannot find user $CertUsername`@localhost which matches Subject ($($Cert.Subject)) on certificate"
			break
		}
		
		if ("CN=$($env:UserName)" -ne $Cert.Subject) {
			# $CurrentUser = $env:UserName
			# $Username = Read-Host -Prompt "Username [$($CurrentUser)]"
			# $Username = ($CurrentUser,$Username)[[bool]$Username]
			$Username = ($Cert.Subject).Substring(3)
			Write-Verbose "Certficate's Subject matches one of local users"
		} else {
			$Username = $env:UserName
			Write-Verbose "Certficate's Subject matches current user"
		}

		#endregion

		#region Remove expired certificates

		$RootStore = "Cert:\LocalMachine\Root"
		$TrustedPeopleStore = "Cert:\LocalMachine\TrustedPeople"

		[System.Security.Cryptography.X509Certificates.X509Certificate2[]] $ExpiredCerts = @(Get-ChildItem -Path $RootStore | Where-Object { $_.Subject -eq $Cert.Subject -and $_.NotAfter -lt [datetime]::Now })

		if ($ExpiredCerts.Count -gt 0) {
			Write-Host "Removing expired certificates"
			# $ExpiredCerts | ForEach-Object { Remove-Cert -StoreName "Root" -Cert $_.Thumbprint }


			$ExpiredCerts = @(Get-ChildItem -Path $TrustedPeopleStore | Where-Object { $_.Subject -eq $Cert.Subject -and $_.NotAfter -lt [datetime]::Now })
			# $ExpiredCerts | ForEach-Object { Remove-Cert -StoreName "Root" -Cert $_.Thumbprint }

			Get-ChildItem -Path WSMan:\localhost\ClientCertificate | Where-Object { $_.Subject -eq "$CertUsername@localhost" } | Remove-Item

		}

		#endregion

		$Thumbprints = @(Get-ChildItem -Path $RootStore | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint })
		
		if ($Thumbprints.Count -gt 0) {
			Write-Host "This certificate already imported"
			break
		}
		
		# import issuing certificate
		
		If (!$Password) {
			$Password = Read-Host -Prompt "Enter password for $($CertUsername)" -AsSecureString
		}
		
		$StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::Root
		
		Add-Cert -StoreName $StoreName -Cert $Cert
		
		# import pubkey
		
		$StoreName = [System.Security.Cryptography.X509Certificates.StoreName]::TrustedPeople
		
		Add-Cert -StoreName $StoreName -Cert $Cert
		
		# $PasswdSecure = ConvertTo-SecureString -String $PasswdStr -AsPlainText -Force
		$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $CertUsername, $Password
		
		# this is the issuer thumbprint which in the case of a self generated cert
		# is the public key thumbprint, additional logic may be required for other
		# scenarios
		$Thumbprint = (Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Subject -eq "CN=$CertUsername" } | Select-Object -first 1).Thumbprint
		
		New-Item -Path WSMan:\localhost\ClientCertificate `
		-Subject "$CertUsername@localhost" `
		-URI * `
		-Issuer $Thumbprint `
		-Credential $Credential `
		-Force
		
		Write-Verbose "Ceritificate added`r`n"
		
		$FileName = (Get-Item $File).Name
		$FileBasename = (Get-Item $File).Basename
		
		Write-Output "Inventory sample vars:`r`n"
		Write-Output "ansible_user=$CertUsername"
		Write-Output "ansible_connection=winrm"
		Write-Output "ansible_winrm_cert_pem=$FileName"
		Write-Output "ansible_winrm_cert_key_pem=$($FileBasename).key.pem"
		Write-Output "ansible_winrm_transport=certificate"
		Write-Output "ansible_winrm_server_cert_validation=ignore"
		
	}
	
	# powercfg.exe -x -monitor-timeout-ac 0
	# USB selective suspend setting ?
	# Wireless Adapter Settings
	
	Function Initialize-Insomnia {
		$PowerSource = "ac"
		$PowerDomains = @("monitor", "disk", "standby", "hibernate")
		Foreach ($PowerDomain in $PowerDomains) {
			$PowerOption = "-$($PowerDomain)-timeout-$($PowerSource)"
			powercfg.exe -x $PowerOption 0
		}
	}
	
	Function New-RemoteAdminUser {
		param(
		[Parameter(Mandatory=$true)]
		[ValidateLength(1,20)]
		[string]
		$Username,
		
		[SecureString]
		$Password,
		
		[string]
		$Description,
		
		[string]
		$FullName
		)

		New-RemoteUser -Username $Username -Password $Password -Description $Description -FullName $FullName -IsAdmin $true
	}
	
	Function New-RemoteUser {
		param(
		[Parameter(Mandatory=$true)]
		[ValidateLength(1,20)]
		[string]
		$Username,
		
		[SecureString]
		$Password,
		
		[string]
		$Description,
		
		[string]
		$FullName,
		
		[bool]
		$IsAdmin = $false
		)
		
		If (!$Password) {
			$Password = Read-Host -AsSecureString
		}
		
		Add-Type -AssemblyName  System.DirectoryServices.AccountManagement
		
		$MachineContext = [DirectoryServices.AccountManagement.ContextType]::Machine
		$PrincipalContext = New-Object 'DirectoryServices.AccountManagement.PrincipalContext' ($MachineContext)
		[DirectoryServices.AccountManagement.UserPrincipal] $User = New-Object 'DirectoryServices.AccountManagement.UserPrincipal' $PrincipalContext
		
		$User.SamAccountName = $Username
		$User.Enabled = 1
		$User.PasswordNeverExpires = 1
		
		$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
		$PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
		$User.SetPassword($PlainPassword)
		
		$User.DisplayName = $FullName
		$User.Description = $Description
		
		$User.Save()
		
		[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)
		
		# $AdminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"
		
		# https://serverfault.com/questions/993482/enable-winrm-for-domain-user
		# (Get-PSSessionConfiguration -Name Microsoft.PowerShell).Permission
		if ($IsAdmin) {
			# [DirectoryServices.AccountManagement.GroupPrincipal]
			$GroupSid = "S-1-5-32-544"			
		} else {
			$GroupSid = "S-1-5-32-580"
		}

		$GroupSidType = [System.DirectoryServices.AccountManagement.IdentityType]::Sid
		$Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($MachineContext, $GroupSidType, $GroupSid)
		
		$Group.Members.Add($PrincipalContext, 'Sid', $User.Sid.Value)
		
		$Group.Save()
		$Group.Dispose()

		return $User
		
	}
	
	
	# Set-Alias install -Value Install-Project
	
	# Export-ModuleMember -Function 'Assign-Cert','Download-Cert','Install-WinRM','Create-CertSelfSigned','Create-CertCOM','Bar','Install-Project' -Alias 'install' -Variable ErrorActionPreference
	
	if (!$BeQuiet) {
		Write-Host "`r`nBoxforming tools for controlled nodes."
		Write-Host "`r`nWinRM setup for controlled machine:"
		Write-Host "Enable-WinRM -Verbose"
		Write-Host "New-RemoteUser -Username"
		Write-Host "New-RemoteAdminUser -Username"
		Write-Host "Import-ClientAuthCert -Url http://site.com/cert.pem  -File C:\Users\admin\cert.pem"
		Write-Host "or"
		Write-Host "Import-ClientAuthCert -File C:\Users\admin\cert.pem"
		Write-Host "Initialize-Insomnia"
		Write-Host ""
	}
	
	Export-ModuleMember -Function 'Initialize-Insomnia','New-RemoteUser','New-RemoteAdminUser','Import-ClientAuthCert','Enable-WinRM','New-ClientAuthCert','Start-CertShareServer' -Variable ErrorActionPreference
	
	#} -AsCustomObject
	
	#Export-ModuleMember -Variable BoxForming
}

# Import-ClientAuthCert -File C:\Users\apla\crt.pem -Verbose 
