# https://gallery.technet.microsoft.com/PS2EXE-Convert-PowerShell-9e4e07f1

# https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-6&viewFallbackFrom=powershell-Microsoft.PowerShell.Core

# Unblock-File

# powershell -executionpolicy RemoteSigned scripts\sysinfo.ps1

function get-Sysinfo {
	param(
		$computername =$env:computername
	)

	$bios = Get-WmiObject Win32_BIOS -ComputerName $computername -ea silentlycontinue
	$baseboard = Get-WmiObject Win32_Baseboard
	$os = Get-WmiObject Win32_OperatingSystem
	$sys = Get-WmiObject Win32_ComputerSystem
	$mem = Get-WmiObject Win32_PhysicalMemory

	[ARRAY]$cpus = Get-WmiObject Win32_Processor
	# Caption           : Intel64 Family 6 Model 78 Stepping 3
	# DeviceID          : CPU0
	# Manufacturer      : GenuineIntel
	# MaxClockSpeed     : 2400
	# Name              : Intel(R) Core(TM) i5-6200U CPU @ 2.30GHz
	# SocketDesignation : U3E1

	#New-Object PSObject -Property @{
	#    Hostname=$Computer
	#    OSArchitecture=$OSArchitecture
	#    SysDrive=$SysDrive
	#    OSVersion=$OSVersion
	#    WinDir=$WinDir
	#}

	$osArchBits = $os.OSArchitecture -replace "\-bit$",""
	$arch = $sys.SystemType -replace "x64-based PC","x86_64"
	$arch = $arch -replace "X86-based PC","i686"
	# https://audministrator.wordpress.com/2016/12/30/windows-core-iot-accessing-raspberry-pi3-wmi-classes-remotely-using-wbem-installed/
	$arch = $arch -replace "ARM-based PC","armv7l" # raspberry pi iot

	$results = New-Object PSObject

	$results | Add-Member noteproperty os "Windows"
	$results | Add-Member noteproperty osArchBits $osArchBits
	$results | Add-Member noteproperty osBuild $os.BuildNumber
	$results | Add-Member noteproperty osVersion $os.Version
	$results | Add-Member noteproperty osName $os.Caption

	$results | Add-Member noteproperty arch $arch

	$results | Add-Member noteproperty productName $sys.Model
	$results | Add-Member noteproperty productVendor $sys.Manufacturer

	[ARRAY]$cpus = Get-CimInstance win32_processor
	$cpuCores = 0
	$cpuThreads = 0
	$cpuSockets = 0

	Foreach ($cpu in $cpus) {
		$cpuSockets++
		$cpuThreads += $cpu.NumberOfLogicalProcessors
		$cpuCores   += $cpu.NumberOfCores
		#$cpu.Name
	}


	$results | Add-Member noteproperty cpuThreads $cpuThreads
	$results | Add-Member noteproperty cpuCores   $cpuCores
	$results | Add-Member noteproperty cpuSockets $cpuSockets

	# https://msdn.microsoft.com/en-us/library/aa394347(v=vs.85).aspx
	$memTotal = 0
	Foreach ($stick in $mem) {
		$memTotal += $stick.Capacity
	}

	$results | Add-Member noteproperty memTotal $memTotal
	#$results | Add-Member noteproperty memTotal $sys.TotalPhysicalMemory

	#(Get-WmiObject -Class Win32_ComputerSystem).SystemType

	$results | Add-Member noteproperty hostname "$($os.CSName)".ToLower()

	$results | Add-Member noteproperty boardName    $baseboard.Product
	$results | Add-Member noteproperty boardVendor  $baseboard.manufacturer
	$results | Add-Member noteproperty boardVersion $baseboard.version

	$results | Add-Member noteproperty biosVersion  $bios.SMBIOSBIOSVersion
	$results | Add-Member noteproperty biosDate     $bios.ConvertToDateTime($bios.ReleaseDate).ToString("yyyy-MM-dd")


	# "arch=x86_64" "cpuThreads=4" "cpuCores=2" "cpuSockets=1" "memTotal=16581780K" "memCMA=0K"

	$results

}



 ####################################Bios function end############################

 #server location

 #$servers = Get-Content -Path C:\servers.txt

 #$infbios =@()


 #foreach($server in $servers){

 #$infbios += get-Bios $server
 #}

 #$infbios | export-csv -path c:\Bios.csv

$sysinfo=get-Sysinfo

$dnsSDArgs  = @("-R", "$($sysinfo.psobject.properties['hostname'])-sysinfo", "_http._tcp", ".", "50105")
$dnsSDArgs += $sysinfo.psobject.properties|%{$_.Name + "=" + $sysinfo.($_.Name)}

&dns-sd $dnsSDArgs

# https://technet.microsoft.com/en-us/library/ee156537.aspx
# wmic systemenclosure get chassistypes
# ChassisTypes
# {9}
