<#

.SYNOPSIS
    This script displays DNS events from the DNS Server analytical event log on local or remote systems.

.DESCRIPTION

    Enabling diagnostic DNS logging is required, this is similar to debug logging, except
    this has has less impact on the performance. Enable enhanced DNS logging is easy, although
    a hotfix perhaps needs to be installed which requires a reboot. The 'How-To' is found here:
    https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v%3Dws.11)

    If you want to query remote computers with RPC/TCP, open the proper ports on the DNS-server(s) with:
    - Get-NetFirewallRule | where DisplayName -like  ‘*Event Log*’ | Enable-NetFirewallRule | Set-NetFireWallRule -RemoteAddress 192.168.2.240

    If you want to run the task of querying DNS events on multiple remote computers in a parallel fashion,
    configure your systems for PowerShell Remoting.

.PARAMETER ComputerName
    An optional parameter that specifies the computername(s) that need to be queried.

    Example:
    -ComputerName DC01, DC02

.PARAMETER ComputerList
    An optional parameter that specifies a text file with computernames that need to be queried.
    The text file should contain a list with computernames whereas each computername is on a new line.
    
    Example:
    -ComputerList D:\targetlist.txt

.PARAMETER Last
    An optional parameter that specifies which last events need to be shown.
    Default is last 2 days.
    
    Examples:
    -Last 2d  # Last 2 days
    -Last 5m  # Last 5 minutes
    -Last 44s # Last 44 seconds
    -Last 5h  # Last 5 hours

.PARAMETER Starttime
    Optional parameter that specifies the start of a timeperiod from which you want to
    display the events.

    Example:
    -Starttime "11/21/2019 12:41 AM"

.PARAMETER Endtime
    Optional parameter that specifies the end of a timeperiod from which you want
    to display the events. Default value is the timestamp of when you run the script.
    
    Example:
    -Endtime "11/21/2019 12:50 AM"

.PARAMETER All
    Optional switch used to display all events.

.PARAMETER WinRM
    Optional switch that specifies that the script needs to run on remote computers
    with PowerShell Remoting. It also makes sure that the task of querying multiple 
    computers in parallel.
    
    If this switch is not used, and a remote computer is provided as parameter 
    (-computername and -computerlist) it uses the default setting which uses 
    RPC/TCP to query the Event Log service on a remote computer.

.PARAMETER Path
    Optional parameter that specifies the path of the DNS Server analytical ETL log.
    Default value is the default Full Path for this log-file.

    Example:
    -Path "%system32%\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl"
    

.PARAMETER Search
    Optional parameter that specifies the domain you want to search the
    related DNS events for.

    Example:
    -Search "example.com"
    -Search "202.42.1.9"

.EXAMPLE
    DNS-tracer.ps1 -Last 2d -Search 'example.com' | ft -wrap
    Running the script as above example, shows all DNS events related to 'example.com' from the last 2 days
    on the local computer.

    - s is Seconds
    - m is Minutes
    - d is Days

.EXAMPLE
    DNS-tracer.ps1 -ComputerName dc01, dns-01 -All
    Displays all dns events of the specified server(s) as argument.

.EXAMPLE
    DNS-tracer.ps1 -Starttime "11/21/2019 12:41 AM" -Endtime "11/21/2019 12:50 AM"
    Above command provides all DNS events within the given timeperiod.

.EXAMPLE
    DNS-tracer.ps1 -ComputerList D:\targetlist.txt
    Displays DNS events of a list with servers provided in the text file.
    It queries only the DNS events of the last 2 days since that is the 
    default value. It can be changed with the -Last parameter.

.EXAMPLE
    DNS-tracer.ps1 -ComputerList D:\targetlist.txt -WinRM -All
    Queries all all given computers for DNS events using PowerShell Remoting
    as oppose to using RPC/TCP.

#>
[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("CN","Computer")]
    [String[]]$ComputerName = $env:computername,

    [Parameter(Mandatory=$false)]
    [String[]]$ComputerList = $null,

    [Parameter(Mandatory=$false)]
    [string]$Last = "1d",

    [Parameter(Mandatory=$false)]
    [DateTime]$Starttime = (Get-Date),

    [Parameter(Mandatory=$false)]
    [DateTime]$Endtime = (Get-Date),

    [Parameter(Mandatory=$false)]
    [switch]$All = $null,

    [Parameter(Mandatory=$false)]
    [switch]$WinRM = $null,

    [Parameter(Mandatory=$false)]
    [String[]]$Path = $null,

    [Parameter(Mandatory=$false)]
    [String[]]$Search = ""
)

$Id = 256,257,260

if (-Not $Path) {
    $SystemDirectory = [Environment]::SystemDirectory
    $Path = $SystemDirectory + "\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl"
}

# Processing given arguments for parameter 'last' and convert to proper timeformat
if ($Last) {

    if ( $Last -match '[0-9]*s$' ) {

        [float]$Last = $Last -replace '[^0-9]',''

        [DateTime]$Starttime = ((Get-Date).AddSeconds(-$Last))

    } elseif ( $Last -match '[0-9]*m$' ) {

        [int]$Last = $Last -replace '[^0-9]',''

        [DateTime]$Starttime = ((Get-Date).AddMinutes(-$Last))

    } elseif ( $Last -match '[0-9]*h$' ) {

        [float]$Last = $Last -replace '[^0-9]',''

        [DateTime]$Starttime = ((Get-Date).AddHours(-$Last))

    } elseif ( $Last -match '[0-9]*d$' ) {

        [float]$Last = $Last -replace '[^0-9]',''

        [DateTime]$Starttime = ((Get-Date).AddDays(-$Last))

    }
}

if ($All) {
    [DateTime]$Starttime = "1/1/1970"
}

# Process the provided computernames as arguments
if ($ComputerList) {

    $ComputerName = get-content -Path $ComputerList

}

Function WinEvents ($Path, $Starttime, $Endtime, $Id, $Search, $ComputerName) {

    $Id = ($Id -split '\s+')
    $ComputerName = ($ComputerName -split '\s+')

    try {

        Get-WinEvent -Oldest -FilterHashTable @{path=$Path; Id=$Id;starttime=$Starttime; endtime=$Endtime} -ComputerName "$ComputerName" -ErrorAction Stop |

            Select MachineName, Id, TimeCreated, Message |

            Where Message -match $Search |

            ForEach {

                $Source = $_.message | select-String -pattern 'Source=([^;]+)' | % {$_.matches.groups[1].value}
                $Destination = $_.message | select-String -pattern 'Destination=([^;]+)' | % {$_.matches.groups[1].value}
                $InterfaceIP = $_.message | select-String -pattern 'InterfaceIP=([^;]+)' | % {$_.matches.groups[1].value}
                $QNAME = $_.message | select-String -pattern 'QNAME=([^;]+)' | % {$_.matches.groups[1].value}
                $Port = $_.message | select-String -pattern 'Port=([^;]+)' | % {$_.matches.groups[1].value}

                if ( $_.Id -eq 256 ) {

                    $Type = "QUERY_RECEIVED"

                } elseif ( $_.Id -eq 257 ) {

                    $Type = "RESPONSE_SUCCESS"

                } elseif ( $_.Id -eq 260 ) {

                    $Type = "RECURSE_QUERY_OUT"

                }

            [pscustomobject]@{

                Time = $_.TimeCreated
                #Id = $_.Id
                Source = $Source
                Destination = $Destination
                InterfaceIP = $InterfaceIP
                QNAME = $QNAME
                Port = $Port
                Type = $Type
                DNSServer = $_.MachineName
            }
        }
    }

    catch [Exception] {

        if ($ComputerName -eq "localhost") {

            Write-Warning "$_ [$Env:ComputerName]"

        } else {

            Write-Warning "$_ [$ComputerName]"

        }
    }

}

# Run get-winevent (via Invoke-Command which uses PowerShell remoting or RPC/TCP)
if ($WinRM) {

    Invoke-Command -ComputerName $ComputerName -ScriptBlock ${function:WinEvents} -argumentlist $Path, $Starttime, $Endtime, $Id, $Search, "localhost" -HideComputerName

} else {

    # Create a dummy file. This is needed due to a bug that fails launching get-winevent on a
    # remote computer if the ETL log file on the local computer does not exist
    if (-Not (Test-Path $Path)) {

        New-Item -Path $Path

    }

    @($ComputerName) |% { WinEvents $Path $Starttime $Endtime $Id $Search $_ }

}
