#!powershell
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

# WANT_JSON
# POWERSHELL_COMMON

# $params is not currently used in this module
# $params = Parse-Args $args;

$result = New-Object psobject @{
    ansible_facts = New-Object psobject
    changed = $false
};

$win32_os = Get-CimInstance Win32_OperatingSystem
$win32_cs = Get-CimInstance Win32_ComputerSystem
$osversion = [Environment]::OSVersion

### ADD VIRTUAL PRODUCT INFO ###
if (((Get-WmiObject win32_bios).Version).tolower().contains("version")) {
        $virtualization_type = "Hyper-V"
}
if (((Get-WmiObject win32_bios).SerialNumber).tolower().contains("vmware")) {
        $virtualization_type = "VMWare"
}
if (((Get-WmiObject win32_bios).Version).tolower().contains("xen")) {
        $virtualization_type = "Xen"
}
if (((Get-WmiObject win32_bios).Version).tolower().contains("vbox")) {
        $virtualization_type = "VirtualBox"
}
###

### ADD CPU INFO ###
$win32_processor = Get-WmiObject -Class Win32_Processor
$processor_count=(,($win32_processor)).count #physical processors
$processor_cores=0;$win32_processor | %{$processor_cores += $_.NumberOfCores} #physical cores
$processor_info=$win32_processor | Select-Object -Property Manufacturer,Name
###

### ADD PHISICAL DISK INFO ###
$arraydevices = @()
$diskdrives = Get-WmiObject -Class Win32_DiskDrive 
foreach ($diskdrive in $diskdrives) {
	$thisdisk = New-Object psobject @{
        deviceid = $diskdrive.deviceid
        size = $diskdrive.size
        caption = $diskdrive.caption
        index = $diskdrive.index
        partitions = $null
    }
    $arraypartition = @()
    $diskpartitions = Get-WmiObject -Class Win32_DiskPartition -filter "DiskIndex=$($diskdrive.index)"
    foreach ($diskpartition in $diskpartitions) {
		$thispartition = $null
        $thispartition = New-Object psobject @{
            numberofblocks = $diskpartition.numberofblocks
            bootpartition = $diskpartition.bootpartition
            name = $diskpartition.name
            primarypartition = $diskpartition.primarypartition
            size = $diskpartition.size
            index = $diskpartition.index
        }
        $arraypartition += $thispartition
    }
    $thisdisk.partitions = $arraypartition
	$arraydevices += $thisdisk
}
###

### ADD LOGICAL DISK INFO ###
$logicaldisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
$arraymounts = @()
foreach ($logicaldisk in $logicaldisks) {
	$thisklogicaldisk = New-Object psobject @{
        deviceid = $logicaldisk.deviceid
        drivetype = $logicaldisk.drivetype
        providername = $logicaldisk.providername
        freespace = $logicaldisk.freespace
        size = $logicaldisk.size
        volumename = $logicaldisk.volumename
    }
	$arraymounts += $thisklogicaldisk
}
###

$capacity = $win32_cs.TotalPhysicalMemory # Win32_PhysicalMemory is empty on some virtual platforms
$netcfg = Get-WmiObject win32_NetworkAdapterConfiguration

$ActiveNetcfg = @(); $ActiveNetcfg+= $netcfg | where {$_.ipaddress -ne $null}
$formattednetcfg = @()
foreach ($adapter in $ActiveNetcfg)
{
    $thisadapter = New-Object psobject @{
    interface_name = $adapter.description
    dns_domain = $adapter.dnsdomain
    default_gateway = $null
    interface_index = $adapter.InterfaceIndex
	nameservers = $null
	search = $null
    }
    
    if ($adapter.defaultIPGateway)
    {
        $thisadapter.default_gateway = $adapter.DefaultIPGateway[0].ToString()
    }
	
	### ADD DNS SERVERS INFO ###
	$thisadapter.nameservers = $adapter.DNSServerSearchOrder 
	$thisadapter.search = $adapter.DNSDomainSuffixSearchOrder 
	###
    
    $formattednetcfg += $thisadapter;$thisadapter = $null
}

### GET ENVIROMENT VARIABLES ###
$listenv = Get-ChildItem env: | Select-Object -Property Name,Value
$dictenv = @{}
foreach ($itemenv in $listenv) {
	$dictenv.Add($itemenv.name,$itemenv.value)
}
$dictenv
###

### GET KB INFO ###
$arrayhotfixes = @()
$arrayhotfixes = Get-HotFix | Select-Object -Property HotFixId | %{$_.HotFixId}
###

Set-Attr $result.ansible_facts "ansible_interfaces" $formattednetcfg

Set-Attr $result.ansible_facts "ansible_architecture" $win32_os.OSArchitecture 

Set-Attr $result.ansible_facts "ansible_hostname" $env:COMPUTERNAME;
Set-Attr $result.ansible_facts "ansible_fqdn" "$([System.Net.Dns]::GetHostByName((hostname)).HostName)"
Set-Attr $result.ansible_facts "ansible_system" $osversion.Platform.ToString()
Set-Attr $result.ansible_facts "ansible_os_family" "Windows"
Set-Attr $result.ansible_facts "ansible_os_name" ($win32_os.Name.Split('|')[0]).Trim()
Set-Attr $result.ansible_facts "ansible_distribution" $osversion.VersionString
Set-Attr $result.ansible_facts "ansible_distribution_version" $osversion.Version.ToString()

$date = New-Object psobject
Set-Attr $date "date" (Get-Date -format d)
Set-Attr $date "year" (Get-Date -format yyyy)
Set-Attr $date "month" (Get-Date -format MM)
Set-Attr $date "day" (Get-Date -format dd)
Set-Attr $date "hour" (Get-Date -format HH)
Set-Attr $date "minute" (Get-Date -format mm)
Set-Attr $date "iso8601" (Get-Date -format s)
Set-Attr $result.ansible_facts "ansible_date_time" $date

### ADD TO ANSIBLE_FACTS INFO ABOUT CPU AND VIRTUALIZATION INFO ###
if ($virtualization_type){
        Set-Attr $result.ansible_facts "ansible_virtualization_type" $virtualization_type
}
Set-Attr $result.ansible_facts "ansible_processor_cores" $processor_cores
Set-Attr $result.ansible_facts "ansible_processor_count" $processor_count
Set-Attr $result.ansible_facts "ansible_processor" $processor_info
###

Set-Attr $result.ansible_facts "ansible_totalmem" $capacity

### ADD TO ANSIBLE_FACTS INFO ABOUT DISK ###
Set-Attr $result.ansible_facts "ansible_devices" $arraydevices
Set-Attr $result.ansible_facts "ansible_mounts" $arraymounts
###

Set-Attr $result.ansible_facts "ansible_lastboot" $win32_os.lastbootuptime.ToString("u")
Set-Attr $result.ansible_facts "ansible_uptime_seconds" $([System.Convert]::ToInt64($(Get-Date).Subtract($win32_os.lastbootuptime).TotalSeconds))

$ips = @()
Foreach ($ip in $netcfg.IPAddress) { If ($ip) { $ips += $ip } }
Set-Attr $result.ansible_facts "ansible_ip_addresses" $ips

### ADD TO ANSIBLE_FACTS INFO ABOUT ENVIROMENT VARIABLES ###
Set-Attr $result.ansible_facts "ansible_env" $dictenv
###

### ADD TO ANSIBLE_FACTS INFO ABOUT INSTALLED KBS ###
Set-Attr $result.ansible_facts "ansible_kbs" $arrayhotfixes 
###

$psversion = $PSVersionTable.PSVersion.Major
Set-Attr $result.ansible_facts "ansible_powershell_version" $psversion

$winrm_https_listener_parent_path = Get-ChildItem -Path WSMan:\localhost\Listener -Recurse | Where-Object {$_.PSChildName -eq "Transport" -and $_.Value -eq "HTTPS"} | select PSParentPath
$winrm_https_listener_path = $null
$https_listener = $null
$winrm_cert_thumbprint = $null
$uppercase_cert_thumbprint = $null

if ($winrm_https_listener_parent_path ) {
    $winrm_https_listener_path = $winrm_https_listener_parent_path.PSParentPath.Substring($winrm_https_listener_parent_path.PSParentPath.LastIndexOf("\"))
}

if ($winrm_https_listener_path)
{
    $https_listener = Get-ChildItem -Path "WSMan:\localhost\Listener$winrm_https_listener_path"
}

if ($https_listener)
{
    $winrm_cert_thumbprint = $https_listener | where {$_.Name -EQ "CertificateThumbprint" } | select Value
}

if ($winrm_cert_thumbprint)
{
   $uppercase_cert_thumbprint = $winrm_cert_thumbprint.Value.ToString().ToUpper()
}

$winrm_cert_expiry = Get-ChildItem -Path Cert:\LocalMachine\My | where Thumbprint -EQ $uppercase_cert_thumbprint | select NotAfter

if ($winrm_cert_expiry) 
{
    Set-Attr $result.ansible_facts "ansible_winrm_certificate_expires" $winrm_cert_expiry.NotAfter.ToString("yyyy-MM-dd HH:mm:ss")
}

Exit-Json $result;
