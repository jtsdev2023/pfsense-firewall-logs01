# script to parse PFsense firewall logs

###################################################################################################
#                                           CONSTANTS                                             #
###################################################################################################




###################################################################################################
#                                           FUNCTIONS                                             #
###################################################################################################


# FUNCTION: filter out RFC 1918 IP addresses, broadcast, multicast addresses, and APIPA addresses
#           returns only public IP addresses
function Test-IPInSubnets {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    # Define the subnets to check
    $subnets = @(
        @{ Network = "10.0.0.0"; CIDR = 8 },
        @{ Network = "172.16.0.0"; CIDR = 12 },
        @{ Network = "192.168.0.0"; CIDR = 16 },
        @{ Network = "255.255.255.255"; CIDR = 32 },
        @{ Network = "224.0.0.0"; CIDR = 4 }
        @{ Network = "169.254.0.0"; CIDR = 16 }
    )

    # Function to convert an IP address to a 32-bit integer
    function ConvertTo-Int32 {
        param ([string]$IP)
        $bytes = $IP -split '\.' | ForEach-Object { [int]$_ }
        return ($bytes[0] -shl 24) -bor ($bytes[1] -shl 16) -bor ($bytes[2] -shl 8) -bor $bytes[3]
    }

    # Convert the IP address to a 32-bit integer
    $ipInt = ConvertTo-Int32 -IP $IPAddress

    foreach ($subnet in $subnets) {
        # Calculate the subnet mask as a 32-bit integer
        $mask = -bnot ([math]::Pow(2, 32 - $subnet.CIDR) - 1)

        # Convert the subnet network address to a 32-bit integer
        $networkInt = ConvertTo-Int32 -IP $subnet.Network

        # Perform bitwise AND between the IP and the mask, and compare with the network
        if (($ipInt -band $mask) -eq $networkInt) {
            return $true
        }
    }

    return $false
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: get ARIN CIDR block info from API
#           returns raw response
function Get-ArinCIDRBlock {
    param (
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )

    $apiUrl = "https://rdap.arin.net/registry/ip/$IPAddress"

    $response = Invoke-WebRequest -Uri $apiUrl -UseBasicParsing

    return $response
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: parse ARIN CIDR block info from API response
#           returns array of processed ARIN CIDR block info
function Invoke-ParseArinCIDRBlock {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$InputArray
    )

    # new array for processed ARIN CIDR block info
    $ArinResult = [System.Collections.ArrayList]::new()

    foreach ($response in $InputArray) {
        $result = [System.Text.Encoding]::UTF8.GetString($response.Content) | ConvertFrom-Json

        # ARIN "cidr0_cidrs" format example:
        # v4prefix    length
        # --------    ------
        # 103.28.54.0     23

        [void]$ArinResult.Add(
            @($result.cidr0_cidrs[0].v4prefix, $result.cidr0_cidrs[0].length, $result.name)
        )
    }
    
    return $ArinResult
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: utility function to convert IP address to 32-bit integer
#           returns 32-bit integer
function Convert-IPToInt {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    # Split the IP address into octets
    $octets = $IPAddress -split '\.'

    # Calculate the 32-bit integer value
    $IntegerValue = ($octets[0] -as [int]) * 16777216 +  # 2^24
                    ($octets[1] -as [int]) * 65536 +     # 2^16
                    ($octets[2] -as [int]) * 256 +       # 2^8
                    ($octets[3] -as [int])               # 2^0

    return $IntegerValue
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: sort ARIN CIDR block info by converting IP CIDR block to 32-bit integer
#           example: 192.168.0.0 = [int]32,32,235,520
#           returns sorted list
function Invoke-SortArinCIDRBlock {
    param (
        [Parameter(Mandatory = $true)]
        [Array]$InputArray
    )

    $IntegerList = [System.Collections.ArrayList]::new()

    # ARIN "cidr0_cidrs" format example:
    # v4prefix    length
    # --------    ------
    # 103.28.54.0     23

    $InputArray | ForEach-Object {
        $ConvertedInt = Convert-IPToInt -IPAddress $_.v4prefix
        [void]$IntegerList.Add(@($_, $ConvertedInt))
    }

    $SortedList = $IntegerList | Sort-Object {
        $_[1] | foreach-object { [int64]$_ }
    } | ForEach-Object {
        $_[0]
    }

    return $SortedList
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 1 - SCP copy log files from PFsense firewall
#           returns nothing
function Invoke-GetFirewallLogs {
    param()

    # get the username
    $UserName = Read-Host "Enter the username for the firewall"
    # get the firewall IP address
    $FirewallIPAddress = Read-Host "Enter the IP address of the firewall"
    
    # string format for scp command
    # example: scp.exe "admin@192.168.1.1:/var/log/filter.log* ."
    $SCP_COMMAND_STR = "{0}@{1}:/var/log/filter.log*" -f $UserName, $FirewallIPAddress

    # scp command - copy log files from firewall to local directory
    scp.exe $SCP_COMMAND_STR "."
        
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 2 - parse downloaded log files
#           returns nothing
function Invoke-ParseFirewallLogs {
    param()

    # parse logs from existing file
    $FilterLogArray = Get-ChildItem -Path $inputFileLocation -Filter "filter.log*"

    # read each pfSense filter log file and append to file
    foreach ($log in $FilterLogArray) {
        $TempFilterLog += Get-Content -Path $log
    }

    Set-Content -Path "step-2-1-tmp-filter-log.txt" -Value $TempFilterLog

    # create a new list to store the log entries that
    # will contain csv formatted IP addresses
    $LogEntryList = [System.Collections.ArrayList]::new()

    # read filter log
    $FilterLog = Get-Content -Path "step-2-1-tmp-filter-log.txt"

    # isolate the CSV portion of the log entries which contain the IP addresses
    foreach ($line in $FilterLog) {
        # use regex to split pfsense filter log entries and
        # just extract the CSV portion
        $SplitPattern = "^\w{3}.*\[\d+\]:\s"
        $LogEntry = [regex]::Split($line, $SplitPattern)

        # regex match on IP addresses in CSV portion of log entry
        $SourceIP, $DestinationIP = 
            [regex]::Matches($LogEntry, "\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b").Value

        # add the dstIP to the list
        [void]$LogEntryList.Add($DestinationIP)
    }

    # get the file destination location
    $OutputFile = "step-2-2-ip-list-filtered.txt"

    # deduplicate the list
    $LogEntryList = $LogEntryList | Sort-Object -Unique

    # write to file
    Set-Content -Path $OutputFile -Value $LogEntryList
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 3 - filter out RFC 1918 IP addresses, broadcast,
#           multicast addresses, and APIPA addresses
#           returns nothing
function Invoke-FilterIPAddresses {
    param()

    # get the input file location/name
    $IPListInputFile = "step-2-2-ip-list-filtered.txt"

    # read the IP list file
    $IPList = Get-Content -Path $IPListInputFile

    $FilteredIPList = [System.Collections.ArrayList]::new()

    # filter IP addresses
    foreach ($ip in $IPList) {
        if (-not (Test-IPInSubnets -IPAddress $ip)) {
            [void]$FilteredIPList.Add($ip)
        }
    }

    # write to file
    $OutputFile = "step-3-filtered-ip-list.txt"

    Set-Content -Path $OutputFile -Value $FilteredIPList
}

# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 4.1 - retrieve ARIN IP address info via API
#           returns array of ARIN API responses in JSON format
function Invoke-GetArinIPAddressInfo {
    param()

    # get filtered IP list file location
    $FilteredIPListFile = "step-3-filtered-ip-list.txt"

    # read the filtered IP list file
    $FilteredIPList = Get-Content -Path $FilteredIPListFile

    # de-duplicate the input list
    $FilteredIPList = $FilteredIPList | Sort-Object -Unique

    # new list to store the ARIN API responses
    $APIResponseList = [System.Collections.ArrayList]::new()

    foreach ($ip in $FilteredIPList) {
        $APIResponse = Get-ArinCIDRBlock -IPAddress $ip
        [void]$APIResponseList.Add($APIResponse)

        # 2 seconds seem like a reasonable delay so ARIN API doesn't block
        Start-Sleep -Seconds 2
    }

    return $APIResponseList

}


# FUNCTION: application step 4.2 - write raw ARIN API JSON response to file
#           returns nothing
function Invoke-WriteArinAPIResponseToFile {
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputArray
    )

    # write raw ARIN API responses to JSON file
    $ArinJsonResponse = $InputArray | ConvertTo-Json -Depth 100 | 
        Out-File -FilePath "step-4-arin-json-response.json"
}


# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 5 - read ARIN API info from file, convert JSON to PowerShell object
#           returns PowerShell object
function Invoke-ReadArinAPIInfoFromFile {
    param()

    # read ARIN API JSON response
    $ArinJsonResponse = Get-Content -Path "step-4-arin-json-response.json" -Raw

    # convert JSON to PowerShell object
    $ArinAPIResponseList = $ArinJsonResponse | ConvertFrom-Json

    return $ArinAPIResponseList
}


# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 6.1 - parse ARIN API JSON response
#           returns nothing
function Invoke-ParseArinAPIResponse {
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputArray
    )

    # parse ARIN API JSON response
    $ArinCidrAndNameList = Invoke-ParseArinCIDRBlock -InputArray $InputArray

    # return list of ARIN API responses filtered to just $_.cidr0_cidrs and $_.name
    return $ArinCidrAndNameList
}


# FUNCTION: application step 6.2 - write ARIN CIDR block info to file
#           returns nothing
function Invoke-WriteArinCIDRBlockToFile {
    # write processed ARIN CIDR block info to file
    param(
        [Parameter(Mandatory = $true)]
        [Array]$InputArray
    )

    # create custom object to use with Format-Table output
    $CidrList = $InputArray | ForEach-Object {
        [PSCustomObject]@{
            CIDR = $_[0];
            LENGTH = $_[1];
            NAME = $_[2]
        }
    }

    # write to file
    $ArinOutputFile = "step-6-arin-cidr-list.txt"
    # de-duplicate the list
    $CidrList = $CidrList | Sort-Object -Unique -Property CIDR, LENGTH

    # write to file
    $CidrList | Sort-Object -Property NAME | Format-Table | Out-File -FilePath $ArinOutputFile
}


# /////////////////////////////////////////////////////////////////////////////////////////////// #


# FUNCTION: application step 7 - archive (zip) ARIN API response file
#           returns nothing
function Invoke-ArchiveArinAPIResponse {
    param()

    # archive ARIN API response file
    Compress-Archive -Path "step-4-arin-json-response.json" `
        -DestinationPath "step-6-arin-json-response-$(Get-Date -Format "yyyyMMddHHmmss").zip"
}



###################################################################################################
#                                              MAIN                                               #
###################################################################################################

# menu banner
$menuBanner = @"

#####################
#   CLI MAIN MENU   #
#####################

"@

# cli menu dict
$CLIMenu = [hashtable]@{
    1 = "Download filter.log from PFsense firewall."
    2 = "Parse logs from existing files."
    3 = "Filter IP addresses from logs."
    4 = "Get ARIN CIDR block info from web API (writes JSON response to file)."
    5 = "Read ARIN API JSON info from file (converts JSON to PowerShell object)."
    6 = "Write parsed ARIN CIDR info to file."
    7 = "Archive (zip) ARIN API JSON response file."
    8 = "Automated (runs through all steps and then exits the program)."
    9 = "Exit"
}

# cli driven menu
while ($true) {
    [Console]::Clear()
    [Console]::ForegroundColor = "Blue"

    Write-Host -Object $menuBanner

    $CLIMenu.GetEnumerator() | Sort-Object | ForEach-Object {
        Write-Host -Object "$($_.Key). $($_.Value)"
    }

    $choice = Read-Host "Enter your choice"

    switch ($choice) {
        1 {
            Invoke-GetFirewallLogs
            break
        }
        2 {
            Invoke-ParseFirewallLogs
            break
        }
        3 {
            Invoke-FilterIPAddresses
            break
        }
        4 {
            $ArinAPIResponseList = Invoke-GetArinIPAddressInfo
            Invoke-WriteArinAPIResponseToFile -InputArray $ArinAPIResponseList

            break
        }
        5 {
            $ArinAPIResponseListFromFile = Invoke-ReadArinAPIInfoFromFile
            break
        }
        6 {
            $ArinCidrAndNameList =
                Invoke-ParseArinCIDRBlock -InputArray $ArinAPIResponseListFromFile

            Invoke-WriteArinCIDRBlockToFile -InputArray $ArinCidrAndNameList
            break
        }
        7 {
            Invoke-ArchiveArinAPIResponse
        }
        8 {
            # 1
            Invoke-GetFirewallLogs
            # 2
            Invoke-ParseFirewallLogs
            # 3
            Invoke-FilterIPAddresses
            # 4
            $ArinAPIResponseList = Invoke-GetArinIPAddressInfo
            Invoke-WriteArinAPIResponseToFile -InputArray $ArinAPIResponseList
            # 5
            $ArinAPIResponseListFromFile = Invoke-ReadArinAPIInfoFromFile
            # 6
            $ArinCidrAndNameList =
                Invoke-ParseArinCIDRBlock -InputArray $ArinAPIResponseListFromFile
            Invoke-WriteArinCIDRBlockToFile -InputArray $ArinCidrAndNameList
            # 7
            Invoke-ArchiveArinAPIResponse

            return $false | Out-Null
        }
        9 {
            return $false | Out-Null
        }
    }
}
