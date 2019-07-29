#  . { iwr -useb http://apla.me/__2.ps1 } | iex
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


New-Module -Name BoxForming  -ScriptBlock {
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

	# https://github.com/ansible/ansible/blob/devel/examples/scripts/ConfigureRemotingForAnsible.ps1
	Function New-ClientAuthCert {
		Param (
			[string]$Username = $env:USERNAME,
			[string]$SubjectName = "CN=$Username",
			[datetime]$NotBefore = [DateTime]::Now.AddDays(-1),
			[datetime]$NotAfter = $NotBefore.AddDays(365*10),
			[string]$AlgorithmName = "RSA",
			[int]$KeyLength = 2048,
			[string] $ProviderName = "Microsoft Enhanced Cryptographic Provider v1.0",
			[Security.Cryptography.X509Certificates.X509ExtensionCollection]$CustomExtension,
			[ValidateSet('MD5','SHA1','SHA256','SHA384','SHA512')]
			[string]$SignatureAlgorithm = "SHA256",
			[string]$Path = "$env:HOMEDRIVE$env:HOMEPATH\$Username"
		)

		# https://blog.keyfactor.com/creating-a-self-signed-ssl-certificate-using-powershell
		
		#New-Variable -Name PFXExportEEOnly -Value 0x0 -Option Constant
		
		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-encodingtype
		New-Variable -Name EncodingType -Value @{
			Base64 = 0x1 # EncodingType.XCN_CRYPT_STRING_BASE64
			Binary = 0x2 # EncodingType.XCN_CRYPT_STRING_BINARY
		} -Option Constant

		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509privatekeyexportflags
		New-Variable -Name X509PrivateKeyExportFlags -Value @{
			Plaintext = 0x2 # X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG
		} -Option Constant

		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-alternativenametype
		New-Variable -Name AlternativeNameType -Value @{
			UPN = 0xb # AlternativeNameType.XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
		} -Option Constant
		
		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509keyspec
		New-Variable -Name X509KeySpec -Value @{
			Exchange = 0x1 # X509KeySpec.XCN_AT_KEYEXCHANGE
			Signature = 0x2 # X509KeySpec.XCN_AT_SIGNATURE
		} -Option Constant

	#region Subject

		$SubjectDN = New-Object -Com X509Enrollment.CX500DistinguishedName
		$SubjectDN.Encode($SubjectName, 0x0)

	#endregion

	#region Private Key

		$Alg = New-Object -Com X509Enrollment.CObjectId
		$Alg.InitializeFromValue(([Security.Cryptography.Oid]$AlgorithmName).Value)

		[String[]]$KeyUsageOpts = ("DigitalSignature", "KeyEncipherment")
		$KeyUsage = New-Object -Com X509Enrollment.CX509ExtensionKeyUsage
		$KeyUsage.InitializeEncode([int][Security.Cryptography.X509Certificates.X509KeyUsageFlags]($KeyUsageOpts))
		$KeyUsage.Critical = $false

		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509privatekey
		$PrivateKey = New-Object -Com X509Enrollment.CX509PrivateKey -Property @{
			# Description = 
			FriendlyName = "Ansible WinRM PK"
			ProviderName = $ProviderName
			Algorithm = $Alg
			# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/ne-certenroll-x509keyspec
			KeySpec = $X509KeySpec.Exchange
			Length = $KeyLength
			MachineContext = 1
			ExportPolicy = $X509PrivateKeyExportFlags.Plaintext
			# KeyUsage = $KeyUsage
		}

		$PrivateKey.Create()

		# $PrivateKey.Export("BCRYPT_PRIVATE_KEY_BLOB", $XCN_CRYPT_STRING_BASE64)
		# https://docs.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey ???
		$PKData = $PrivateKey.Export("PRIVATEBLOB", $EncodingType.Base64)

		$RSA = New-Object System.Security.Cryptography.RSACryptoServiceProvider
		$RSA.ImportCspBlob([System.Convert]::FromBase64String($PKData))

		# https://stackoverflow.com/questions/23734792/c-sharp-export-private-public-rsa-key-from-rsacryptoserviceprovider-to-pem-strin

		$assemblies=(
			"System",
			"System.IO"
		)

		$source=@"
using System;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Boxforming {

	public class RsaCsp2DerConverter {
		private const int MaximumLineLength = 64;

		// Based roughly on: http://stackoverflow.com/a/23739932/1254575

		public RsaCsp2DerConverter() {

		}

		private static byte[] Encode(byte[] inBytes, bool useTypeOctet = true) {
			int length = inBytes.Length;
			var bytes = new List<byte>();

			if (useTypeOctet == true)
				bytes.Add(0x02); // INTEGER

			bytes.Add(0x84); // Long format, 4 bytes
			bytes.AddRange(BitConverter.GetBytes(length).Reverse());
			bytes.AddRange(inBytes);

			return bytes.ToArray();
		}

		public static String PemEncode(byte[] bytes) {
			//if (bytes == null)
			//   throw new ArgumentNullException(nameof(bytes));

			var base64 = Convert.ToBase64String(bytes);

			StringBuilder b = new StringBuilder();
			
			b.Append("-----BEGIN RSA PRIVATE KEY-----\n");

			for (int i = 0; i < base64.Length; i += MaximumLineLength) {
				b.Append(base64.Substring(i, Math.Min(MaximumLineLength, base64.Length - i)));
				b.Append("\n");
			}

			b.Append("-----END RSA PRIVATE KEY-----\n");

			return b.ToString();
		}

		public static byte[] SerializeList(List<byte[]> list) {
			//if (list == null)
			//   throw new ArgumentNullException(nameof(list));

			var keyBytes = list.Select(e => Encode(e)).SelectMany(e => e).ToArray();

			var binaryWriter = new BinaryWriter(new MemoryStream());
			binaryWriter.Write((byte) 0x30); // SEQUENCE
			binaryWriter.Write(Encode(keyBytes, false));
			binaryWriter.Flush();

			var result = ((MemoryStream) binaryWriter.BaseStream).ToArray();

			binaryWriter.BaseStream.Dispose();
			binaryWriter.Dispose();

			return result;
		}
	}
}
"@

		Add-Type -ReferencedAssemblies $assemblies -TypeDefinition $source -Language CSharp

		if ($RSA.PublicOnly) {
			# throw new ArgumentException("CSP does not contain a private key!", nameof(csp));
		}

		$PKParams = $RSA.ExportParameters($true);

		$List = New-Object System.Collections.Generic.List[byte[]]
		$List.Add([Byte[]] (,0x00))
		$List.Add($PKParams.Modulus)
		$List.Add($PKParams.Exponent)
		$List.Add($PKParams.D)
		$List.Add($PKParams.P)
		$List.Add($PKParams.Q)
		$List.Add($PKParams.DP)
		$List.Add($PKParams.DQ)
		$List.Add($PKParams.InverseQ)

		$PKPEMBytes = [Boxforming.RsaCsp2DerConverter]::SerializeList($List)

		$PKPEMString = [Boxforming.RsaCsp2DerConverter]::PemEncode($PKPEMBytes)

		[System.IO.File]::WriteAllText("$Path.key.pem", $PKPEMString)

	#endregion

	#region Certificate Init

		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509certificaterequestcertificate
		$Cert = New-Object -Com X509Enrollment.CX509CertificateRequestCertificate
		if ($PrivateKey.MachineContext) {
			$Cert.InitializeFromPrivateKey(0x2, $PrivateKey, "") # MachineContext = 0x2
		} else {
			$Cert.InitializeFromPrivateKey(0x1, $PrivateKey, "") # UserContext = 0x1
		}
		$Cert.Subject   = $SubjectDN
		$Cert.Issuer    = $Cert.Subject
		$Cert.NotBefore = $NotBefore
		$Cert.NotAfter  = $NotAfter

		$SigOId = New-Object -ComObject X509Enrollment.CObjectId
		$SigOId.InitializeFromValue(([Security.Cryptography.Oid]$SignatureAlgorithm).Value)
		$Cert.SignatureInformation.HashAlgorithm = $SigOId

	#endregion

	#region Enhanced Key Usages (EKU)
		$ClientAuthOId = New-Object -Com X509Enrollment.CObjectId
		# https://docs.microsoft.com/en-us/windows/win32/api/certenroll/nn-certenroll-ix509extensionenhancedkeyusage
		$ClientAuthOId.InitializeFromValue("1.3.6.1.5.5.7.3.2")
		$EKUOIds = new-object -Com X509Enrollment.CObjectIds
		$EKUOIds.Add($ClientAuthOId)
		$EKUExt = New-Object -Com X509Enrollment.CX509ExtensionEnhancedKeyUsage
		$EKUExt.InitializeEncode($EKUOIds)

		$Cert.X509Extensions.Add($EKUExt)

	#endregion

	#region Subject Alternative Name (SAN)
		$SANExt = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
		$Names  = New-Object -ComObject X509Enrollment.CAlternativeNames
		$Name   = New-Object -ComObject X509Enrollment.CAlternativeName

		# $AuthUPN = "otherName:1.3.6.1.4.1.311.20.2.3;UTF8:kiosk@localhost"
		$AuthUPN = "$Username@localhost"
		$Name.InitializeFromString($AlternativeNameType.UPN, $AuthUPN)
		$Names.Add($Name)
		$SANExt.InitializeEncode($Names)
		
		$Cert.X509Extensions.Add($SANExt)

	#endregion

	#region Certificate Export

		#foreach ($item in $ExtensionsToAdd) {
		#	$Cert.X509Extensions.Add((Get-Variable -Name $item -ValueOnly))
		#}

		$Cert.Encode()
		
		# export the public key
		$PemOutput = @()
		$PemOutput += "-----BEGIN CERTIFICATE-----"
		# $PemOutput += [Convert]::ToBase64String($Cert.RawData()) -replace ".{64}", "$&`n"
		$PemOutput += $Cert.RawData() -Split "`r`n"
		# $PemOutput = $PemOutput[0..$($PemOutput.Count - 2)] 
		$PemOutput[$PemOutput.Length - 1] = "-----END CERTIFICATE-----" # removed extra newline
		[System.IO.File]::WriteAllLines("$Path.crt.pem", $PemOutput)

		return New-Object Security.Cryptography.X509Certificates.X509Certificate2 @(,[System.Convert]::FromBase64String($Cert.RawData()))

	#endregion

	}

	Function Add-Cert {
		Param (
			$StoreName,
			$Cert
		)

		$StoreLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine
		$Store = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Store -ArgumentList $StoreName, $StoreLocation
		$Store.Open("MaxAllowed")
		$Store.Add($Cert)
		$Store.Close()
		
	}

	
	Function Import-ClientAuthCert {
		[CmdletBinding()]
		Param (
			[string] $File,
			[string] $Url,
			[SecureString] $Password
		)
		
		if ($Url) {
			$startTime = Get-Date

			Invoke-WebRequest -Uri $Url -OutFile $File
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

		$Thumbprints = @(Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Thumbprint -eq $Cert.Thumbprint })

		if ($Thumbprints.Count -gt 0) {
			Write-Verbose "This certificate already imported"
		}

		# import issuing certificate

		#if ([string]::IsNullOrWhiteSpace($Username)) {
		#	$Username = $env:UserName
		#}

		# remove CN= from cert subject
		$CertUsername = ($Cert.Subject).Substring(3)

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
		$Thumbprint = (Get-ChildItem -Path cert:\LocalMachine\root | Where-Object { $_.Subject -eq "CN=$CertUsername" }).Thumbprint

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

	# https://github.com/ChristopherGLewis/PowerShellWebServers
	# Why not System.Net.HttpListener?
	# https://stackoverflow.com/questions/4019466/httplistener-access-denied
	# netsh http add urlacl url=http://+:80/ user=Everyone
	# In spanish-language systems, do: user=Todos

	# https://gist.github.com/Tiberriver256/868226421866ccebd2310f1073dd1a1e
	# https://github.com/TLaborde/NodePS
	# https://github.com/Jan-Ka/coms
	<#
	.Synopsis
		Starts Web Server to handle simple requests
	.DESCRIPTION

	.EXAMPLE
		
	.EXAMPLE
	Get "/Process" { Get-Process | ConvertTo-Json } 
	#>
	Function Start-WebServer {
		Param(
			[int]$Port=8081,
			[hashtable]$Handlers,
			[bool]$WWWRoot,
			[string]$IndexFilename = "index.html"
		)

		$Listener = New-Object System.Net.Sockets.TcpListener(
			[System.Net.IPAddress]::Any, $Port
		)

		if ($WWWRoot) {
			New-PSDrive -Name WWWDrive -PSProvider FileSystem -Root $WWWRoot.Path
		}

		$Listener.Start()

		$ContentType = "application/x-pem-file" # "application/x-x509-ca-cert" # application/x-pem-file

        try {
			do {
				# TODO: https://stackoverflow.com/questions/51218257/await-async-c-sharp-method-from-powershell
				$ClientTask = $Listener.AcceptTcpClientAsync()
				while (-not $ClientTask.AsyncWaitHandle.WaitOne(200)) { }
				$Client = $ClientTask.GetAwaiter().GetResult()

				$Stream = $Client.GetStream();
				$Writer = New-Object System.IO.StreamWriter $Stream
				$Reader = New-Object System.IO.StreamReader ($Stream, [System.Text.Encoding]::ASCII) # Request.ContentEncoding
				
				# $LineTask = $Reader.ReadLineAsync()
				# while (-not $LineTask.AsyncWaitHandle.WaitOne(200)) { }
				# $Line = $LineTask.GetAwaiter().GetResult()

				$Line = $Reader.ReadLine()

				if ($Line -eq $null) {
					Write-Host "<< Client unexpectedly closed connection"
					# TODO: close connection
					$Writer.Close()
					continue
				}
				if (!$Line.StartsWith('GET')) {
					Write-Host "<< Not a GET request $Line"
					$Writer.Write("HTTP/1.1 405 OK`r`nAllow: GET`r`nConnection: close`r`n`r`nOnly GET Allowed`r`n")
					$Writer.Close()
					continue
				}
					
				$HttpVersionOffset = $Line.IndexOf(" HTTP/1.1")
				if ($HttpVersionOffset -eq -1) {
					$RequestUrl = $Line.Substring(4)
				} else {
					$RequestUrl = $Line.Substring(4, $HttpVersionOffset - 4)
				}
				
				Write-Host "<<< $RequestUrl"

				if ($Handlers.ContainsKey($RequestUrl)) {
					$CmdResult = Invoke-Command -ScriptBlock $Handlers[$RequestUrl] -ArgumentList $Writer
					Write-Host $CmdResult
					# Invoke-Expression $Handlers[$RequestUrl] $Writer
					continue
				}

				if ($WWWRoot) {
					$FSUrl = $RequestUrl
					if ($FSUrl.EndsWith('/')) {$FSUrl += $IndexFilename}
					$Content = Get-Content -Encoding Byte -Path "WWWDrive:$RequestUrl"
					$ContentType = [System.Web.MimeMapping]::GetMimeMapping("WWWDrive:$RequestUrl")
					$ContentLength = $Content.Length
					$Writer.Write("HTTP/1.1 200 OK`r`nConnection: close`r`nContent-Type: $ContentType`r`nContent-Length: $ContentLength`r`n`r`n")
					$Writer.Flush()
					$Write.BaseStream.Write($Content, 0, $Content.Length)
					$Writer.Close()
					continue
				}
				

				$Writer.Write("HTTP/1.1 404 Not Found`r`nConnection: close`r`n`r`n$RequestUrl Not Found`r`n")
				$Writer.Close()
			} while ($true)
        } finally {
            # https://stackoverflow.com/questions/1710698/gracefully-stopping-in-powershell
            $Listener.Stop()
        }
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

	Function New-LocalAdminUser {
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

		If (!$Password) {
			$Password = Read-Host -AsSecureString
		}

		Add-Type -AssemblyName  System.DirectoryServices.AccountManagement

		$MachineContext = [DirectoryServices.AccountManagement.ContextType]::Machine
		$PrincipalContext = New-Object 'DirectoryServices.AccountManagement.PrincipalContext' ($MachineContext)
		$User = New-Object 'DirectoryServices.AccountManagement.UserPrincipal' $PrincipalContext
		
		$User.SamAccountName = $Username
		$User.Enabled = 1
		$User.PasswordNeverExpires = 1

		$PlainPassword = ConvertFrom-SecureString $Password
		$User.SetPassword($PlainPassword)

		$User.DisplayName = $FullName
		$User.Description = $Description

		$User.Save()

		# $AdminGroup = Get-CimInstance Win32_Group -Filter "LocalAccount=True AND SID='S-1-5-32-544'"

		# [DirectoryServices.AccountManagement.GroupPrincipal]
		$GroupSidType = [System.DirectoryServices.AccountManagement.IdentityType]::Sid
		$Group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($MachineContext, $GroupSidType, "S-1-5-32-544")

		$Group.Members.Add($PrincipalContext, 'Sid', $User.Sid.Value)

		$Group.Save()
		$Group.Dispose()

		return $User
	
	}

	Function Start-CertShareServer {
		Param(
			[int] $Port = 50580
		)
		Start-WebServer -Port $Port -Handlers @{
			"/favicon.ico" = {
				param($Writer)

				# [Byte[]] (,0x00)

				$Message = "FAVICON"

				$TransparentIcoBytes = [System.Convert]::FromBase64String("AAABAAEAEBACAAEAAQCwAAAAFgAAACgAAAAQAAAAIAAAAAEAAQAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA////AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA//8AAP//AAD//wAA")
		
				$Writer.Write("HTTP/1.1 200 OK`r`n")
						
				$Writer.Write("Content-Type: image/x-icon`r`n")
				$Writer.Write("Connection: close`r`n`r`n")
				$Writer.Flush()
				$Writer.BaseStream.Write($TransparentIcoBytes, 0, $TransparentIcoBytes.Length)
				$Writer.Close()
				return "FAVICON"
			}
			"/" = {
				param($Writer)

				$Message = "ROOT"

				$Writer.Write("HTTP/1.1 200 OK`r`nConnection: close`r`n`r`n$Message`r`n")
				$Writer.Close()

				return "ROOT"
			}
		}
	} 

	# Set-Alias install -Value Install-Project

	# Export-ModuleMember -Function 'Assign-Cert','Download-Cert','Install-WinRM','Create-CertSelfSigned','Create-CertCOM','Bar','Install-Project' -Alias 'install' -Variable ErrorActionPreference

	Write-Host "`r`nCommands:"
	Write-Host "`r`nWinRM setup for controlled machine:"
	Write-Host "Configure-WinRM -Verbose"
	Write-Host "Import-ClientAuthCert -Url http://site.com/cert.pem  -File C:\Users\admin\cert.pem"
	Write-Host "or"
	Write-Host "Import-ClientAuthCert -File C:\Users\admin\cert.pem"
	Write-Host "Initialize-Insomnia"
	Write-Host "`r`nTools for controller machine:"
	Write-Host "New-ClientAuthCert -Username"
	Write-Host "Start-CertShareServer"
	Write-Host ""

	Export-ModuleMember -Function 'Initialize-Insomnia','New-LocalAdminUser','Import-ClientAuthCert','Enable-WinRM','New-ClientAuthCert','Start-CertShareServer' -Variable ErrorActionPreference

	#} -AsCustomObject

#Export-ModuleMember -Variable BoxForming
}
