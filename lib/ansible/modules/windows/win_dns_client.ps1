#!powershell

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.Legacy

Set-StrictMode -Version 2

$ErrorActionPreference = "Stop"
$ConfirmPreference = "None"

Set-Variable -Visibility Public -Option ReadOnly,AllScope,Constant -Name "AddressFamilies" -Value @{
    [System.Net.Sockets.AddressFamily]::InterNetworkV6 = 'IPv6'
    [System.Net.Sockets.AddressFamily]::InterNetwork = 'IPv4'
}

$result = @{
    changed = $false
    adapters = @()
}

$params = Parse-Args -arguments $args -supports_check_mode $true
Set-Variable -Visibility Public -Option ReadOnly,AllScope,Constant -Name "log_path" -Value (
    Get-AnsibleParam $params "log_path"
)
$adapter_names = Get-AnsibleParam $params "adapter_names" -Default "*"
$dns_servers = Get-AnsibleParam $params "dns_servers" -aliases "ipv4_addresses","ip_addresses","addresses" -FailIfEmpty $result
$check_mode = Get-AnsibleParam $params "_ansible_check_mode" -Default $false


Function Write-DebugLog {
    Param(
    [string]$msg
    )

    $DebugPreference = "Continue"
    $ErrorActionPreference = "Continue"
    $date_str = Get-Date -Format u
    $msg = "$date_str $msg"

    Write-Debug $msg
    if($log_path) {
        Add-Content $log_path $msg
    }
}

Function Get-NetAdapterInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String]$Name = "*"
    )

    Process {
        if (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapter_info = Get-NetAdapter @PSBoundParameters |
                Select-Object -Property Name, InterfaceIndex, InterfaceGuid
        } else {
            # Older hosts 2008/2008R2 don't have Get-NetAdapter, fallback to deprecated Win32_NetworkAdapter
            $cim_params = @{
                ClassName = "Win32_NetworkAdapter"
                Property = "InterfaceIndex", "NetConnectionID"
            }

            if ($Name.Contains("*")) {
                $cim_params.Filter = "NetConnectionID LIKE '$($Name.Replace("*", "%"))'"
            } else {
                $cim_params.Filter = "NetConnectionID = '$Name'"
            }

            $adapter_info = Get-CimInstance @cim_params | Select-Object -Property @(
                @{Name="Name"; Expression={$_.NetConnectionID}},
                @{Name="InterfaceIndex"; Expression={$_.InterfaceIndex}}
            )
        }

        # Need to filter the adapter that are not IPEnabled, while we are at it, also get the DNS config.
        $net_info = $adapter_info | ForEach-Object -Process {
            $cim_params = @{
                ClassName = "Win32_NetworkAdapterConfiguration"
                Filter = "InterfaceIndex = $($_.InterfaceIndex)"
                Property = "DNSServerSearchOrder", "IPEnabled", "SettingID"
            }
            $adapter_config = Get-CimInstance @cim_params |
                Add-Member -MemberType AliasProperty -Name InterfaceGuid -Value SettingID -Force -PassThru

            if ($adapter_config.IPEnabled -eq $false) {
                return
            }

            $reg_info = $adapter_config |
                Get-RegistryNameServerInfo

            [PSCustomObject]@{
                Name = $_.Name
                InterfaceIndex = $_.InterfaceIndex
                InterfaceGuid = $_.InterfaceGuid
                RegInfo = $reg_info
            }
        }

        if (@($net_info).Count -eq 0 -and -not $Name.Contains("*")) {
            throw "Get-NetAdapterInfo: Failed to find network adapter(s) that are IP enabled with the name '$Name'"
        }

        $net_info
    }
}

Function Get-RegistryNameServerInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true,Mandatory=$true)]
        [System.Guid]
        $InterfaceGuid
    )

    Begin {
        Set-StrictMode -Off  # Current Scope

        $v4Items = @{
            Interface = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{{{0}}}'
            StaticNameServer = 'NameServer'
            DhcpNameServer = 'DhcpNameServer'
            EnableDhcp = 'EnableDHCP'
        }

        $v6Items = @{
            Interface = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\{{{0}}}'
            StaticNameServer = 'NameServer'
            DhcpNameServer = 'Dhcpv6DNSServers'
            EnableDhcp = 'EnableDHCP'
        }
    }

    Process {
        $return = @()

        $v4Path = $v4Items.Interface -f $InterfaceGuid
        $v6Path = $v6Items.Interface -f $InterfaceGuid

        if (($iface = Get-Item -LiteralPath $v4Path -ErrorAction Ignore)) {
            $iprop = $iface | Get-ItemProperty
            $v4Info = @{
                AddressFamily = [System.Net.Sockets.AddressFamily]::InterNetwork
                UsingDhcp = $iprop.($v4Items.EnableDhcp) -as [bool]
                EffectiveNameServers = @()
                DhcpAssignedNameServers = @()
                NameServerBadFormat = $false
            }

            if (($ns = $iprop.($v4Items.DhcpNameServer))) {
                $v4Info.EffectiveNameServers = $v4Info.DhcpAssignedNameServers = $ns.Split(' ')
            }

            if (($ns = $iprop.($v4Items.StaticNameServer))) {
                $v4Info.EffectiveNameServers = $v4Info.StaticNameServers = $ns -split '[,;\ ]'
                $v4Info.UsingDhcp = $false
                $v4Info.NameServerBadFormat = $ns -match '[;\ ]'
            }

            $v4Info
        }

        if (($iface = Get-Item -LiteralPath $v6Path -ErrorAction Ignore)) {
            $iprop = $iface | Get-ItemProperty
            $v6Info = @{
                AddressFamily = [System.Net.Sockets.AddressFamily]::InterNetworkV6
                UsingDhcp = $iprop.($v6Items.EnableDhcp) -as [bool]
                EffectiveNameServers = @()
                DhcpAssignedNameServers = @()
                NameServerBadFormat = $false
            }

            if (($ns = $iprop.($v6Items.DhcpNameServer))) {
                $v6Info.EffectiveNameServers = $v6Info.DhcpAssignedNameServers = $ns.Split(' ')
            }

            if (($ns = $iprop.($v6Items.StaticNameServer))) {
                $v6Info.EffectiveNameServers = $v6Info.StaticNameServers = $ns -split '[,;\ ]'
                $v6Info.UsingDhcp = $false
                $v6Info.NameServerBadFormat = $ns -match '[;\ ]'
            }

            $v6Info
        }

        $return
    }
}

Function Get-NetAdapterInfo {
    [CmdletBinding()]
    Param (
        [Parameter(ValueFromPipeline=$true)]
        [String]$Name = "*"
    )

    Process {
        if (Get-Command -Name Get-NetAdapter -ErrorAction SilentlyContinue) {
            $adapter_info = Get-NetAdapter @PSBoundParameters |
                Select-Object -Property Name, InterfaceIndex, InterfaceGuid
        } else {
            # Older hosts 2008/2008R2 don't have Get-NetAdapter, fallback to deprecated Win32_NetworkAdapter
            $cim_params = @{
                ClassName = "Win32_NetworkAdapter"
                Property = "InterfaceIndex", "NetConnectionID"
            }

            if ($Name.Contains("*")) {
                $cim_params.Filter = "NetConnectionID LIKE '$($Name.Replace("*", "%"))'"
            } else {
                $cim_params.Filter = "NetConnectionID = '$Name'"
            }

            $adapter_info = Get-CimInstance @cim_params | Select-Object -Property @(
                @{Name="Name"; Expression={$_.NetConnectionID}},
                @{Name="InterfaceIndex"; Expression={$_.InterfaceIndex}}
            )
        }

        # Need to filter the adapter that are not IPEnabled, while we are at it, also get the DNS config.
        $net_info = $adapter_info | ForEach-Object -Process {
            $cim_params = @{
                ClassName = "Win32_NetworkAdapterConfiguration"
                Filter = "InterfaceIndex = $($_.InterfaceIndex)"
                Property = "DNSServerSearchOrder", "IPEnabled", "SettingID"
            }
            $adapter_config = Get-CimInstance @cim_params |
                Add-Member -MemberType AliasProperty -Name InterfaceGuid -Value SettingID -Force -PassThru

            if ($adapter_config.IPEnabled -eq $false) {
                return
            }

            $reg_info = $adapter_config |
                Get-RegistryNameServerInfo

            [PSCustomObject]@{
                Name = $_.Name
                InterfaceIndex = $_.InterfaceIndex
                InterfaceGuid = $_.InterfaceGuid
                RegInfo = $reg_info
            }
        }

        if (@($net_info).Count -eq 0 -and -not $Name.Contains("*")) {
            throw "Get-NetAdapterInfo: Failed to find network adapter(s) that are IP enabled with the name '$Name'"
        }

        $net_info
    }
}

# minimal impl of Set-DnsClientServerAddress for 2008/2008R2
Function Set-DnsClientServerAddressLegacy {
    Param(
        [int]$InterfaceIndex,
        [Array]$ServerAddresses=@(),
        [switch]$ResetServerAddresses
    )
    $cim_params = @{
        ClassName = "Win32_NetworkAdapterConfiguration"
        Filter = "InterfaceIndex = $InterfaceIndex"
        KeyOnly = $true
    }
    $adapter_config = Get-CimInstance @cim_params

    If($ResetServerAddresses) {
        $arguments = @{}
    }
    Else {
        $arguments = @{ DNSServerSearchOrder = [string[]]$ServerAddresses }
    }
    $res = Invoke-CimMethod -InputObject $adapter_config -MethodName SetDNSServerSearchOrder -Arguments $arguments

    If($res.ReturnValue -ne 0) {
        throw "Set-DnsClientServerAddressLegacy: Error calling SetDNSServerSearchOrder, code $($res.ReturnValue))"
    }
}

If(-not $(Get-Command Set-DnsClientServerAddress -ErrorAction SilentlyContinue)) {
    New-Alias Set-DnsClientServerAddress Set-DnsClientServerAddressLegacy
}

Function Test-DnsClientMatch {
    Param(
        [PSCustomObject]$AdapterInfo,
        [System.Net.IPAddress[]] $dns_servers
    )
    Write-DebugLog ("Getting DNS config for adapter {0}" -f $AdapterInfo.Name)

    foreach ($proto in $AdapterInfo.RegInfo) {
        $desired_dns = if ($dns_servers) {
            $dns_servers | Where-Object -FilterScript {$_.AddressFamily -eq $proto.AddressFamily}
        }

        $current_dns = [System.Net.IPAddress[]]($proto.EffectiveNameServers)
        Write-DebugLog ("Current DNS settings for '{1}' Address Family: {0}" -f ([string[]]$current_dns -join ", "),$AddressFamilies[$proto.AddressFamily])

        if ($proto.NameServerBadFormat) {
            Write-DebugLog "Malicious DNS server format detected. Will set DNS desired state."
            return $false
            # See: https://www.welivesecurity.com/2016/06/02/crouching-tiger-hidden-dns/
        }

        if ($proto.UsingDhcp -and -not $desired_dns) {
            Write-DebugLog "DHCP DNS Servers are in use and no DNS servers were requested (DHCP is desired)."
        } else {
            if ($desired_dns -and -not $current_dns) {
                Write-DebugLog "There are currently no DNS servers in use, but they should be present."
                return $false
            }

            if ($current_dns -and -not $desired_dns) {
                Write-DebugLog "There are currently DNS servers in use, but they should be absent."
                return $false
            }

            if ($null -ne $current_dns -and
                $null -ne $desired_dns -and
                (Compare-Object -ReferenceObject $current_dns -DifferenceObject $desired_dns -SyncWindow 0)) {
                Write-DebugLog "Static DNS servers are not in the desired state (incorrect or in the wrong order)."
                return $false
            }
        }

        Write-DebugLog ("Current DNS settings match ({0})." -f ([string[]]$desired_dns -join ", "))
    }
    return $true
}


Function Assert-IPAddress {
    Param([string] $address)

    $addrout = $null

    return [System.Net.IPAddress]::TryParse($address, [ref] $addrout)
}

Function Set-DnsClientAddresses
{
    Param(
        [PSCustomObject]$AdapterInfo,
        [System.Net.IPAddress[]] $dns_servers
    )

    Write-DebugLog ("Setting DNS addresses for adapter {0} to ({1})" -f $AdapterInfo.Name, ([string[]]$dns_servers -join ", "))

    If ($dns_servers) {
        Set-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -ServerAddresses $dns_servers
    } Else {
        Set-DnsClientServerAddress -InterfaceIndex $AdapterInfo.InterfaceIndex -ResetServerAddress
    }
}

if($dns_servers -is [string]) {
    if($dns_servers.Length -gt 0) {
        $dns_servers = @($dns_servers)
    } else {
        $dns_servers = @()
    }
}
# Using object equals here, to check for exact match (without implicit type conversion)
if([System.Object]::Equals($adapter_names, "*")) {
    $adapters = Get-NetAdapterInfo
} else {
    $adapters = $adapter_names | Get-NetAdapterInfo
}

Try {

    Write-DebugLog ("Validating IP addresses ({0})" -f ($dns_servers -join ", "))
    $invalid_addresses = @($dns_servers | Where-Object { -not (Assert-IPAddress $_) })
    if($invalid_addresses.Count -gt 0) {
        throw "Invalid IP address(es): ({0})" -f ($invalid_addresses -join ", ")
    }

    foreach($adapter_info in $adapters) {
        Write-DebugLog ("Validating adapter name {0}" -f $adapter_info.Name)
        $thisAdapter = @{
            name = $adapter_info.Name
            interface_index = $adapter_info.InterfaceIndex
            interface_guid = $adapter_info.InterfaceGuid
        }

        if(-not (Test-DnsClientMatch $adapter_info $dns_servers)) {
            $result.changed = $true
            if(-not $check_mode) {
                Set-DnsClientAddresses $adapter_info $dns_servers

                # Get updated info for output
                $adapter_info.RegInfo = $adapter_info | Get-RegistryNameServerInfo
            } else {
                Write-DebugLog "Check mode, skipping"
            }
        }

        foreach ($proto in $adapter_info.RegInfo) {
            $prefix = $AddressFamilies[$proto.AddressFamily].ToLower()

            foreach ($kv in $proto.GetEnumerator()) {
                $key, $value = $kv.Key, $kv.Value

                if ($null -eq $value -or $key -in @('AddressFamily')) {
                    continue
                }

                $thisAdapter["${prefix}_${key}"] = $value
            }
        }

        $result.adapters += $thisAdapter
    }

    Exit-Json $result

}
Catch {
    $excep = $_

    Write-DebugLog "Exception: $($excep | Out-String)"

    Throw
}
