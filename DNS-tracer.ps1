<#

.SYNOPSIS
This script displays DNS events from the DNS Server analytical event log.

.DESCRIPTION

Enabling diagnostic DNS logging is required, this is similar to debug logging, except
this has has less impact on the performance. Enable enhanced DNS logging is easy, although 
a hotfix perhaps needs to be installed which requires a reboot. The 'How-To' is found here:
https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v%3Dws.11)

A module also needs to be installed: 'PoshRSJob' https://github.com/proxb/PoshRSJob

.EXAMPLE
DNS-tracer.ps1 -last 100m -search 'example.com'
Running the script as above example, shows all DNS events related to 'example.com' from the last 100 minutes.

- s is Seconds
- m is Minutes
- d is Days

.EXAMPLE
DNS-tracer.ps1 -starttime "11/21/2019 12:41 AM" -endtime "11/21/2019 12:50 AM"
Above command provides all DNS events within the given timeperiod.


.EXAMPLE
DNS-tracer.ps1 -computer dc01, dns-01
Displays all dns events of the specified server(s) as argument. 

.EXAMPLE
DNS-tracer.ps1 -computerlist D:\targetlist.txt
Displays all DNS events of a list with servers provided in the text file.

#>

[CmdletBinding()]
Param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias("CN","Computer")]
    [String[]]$ComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory=$false)]
    [string]$last = $null,

    [Parameter(Mandatory=$false)]
    [DateTime]$starttime = (Get-Date),
    
    [Parameter(Mandatory=$false)]
    [DateTime]$endtime = (Get-Date),

    [Parameter(Mandatory=$false)]
    [String[]]$computerlist = $null,

    [Parameter(Mandatory=$false)]
    [String[]]$search = ""
)

$Id = 256,257,260
$SystemDirectory = [Environment]::SystemDirectory
$path = $SystemDirectory + "\winevt\Logs\Microsoft-Windows-DNSServer%4Analytical.etl"

# Processing given arguments for parameter 'last' and convert to proper timeformat
if ($last -ne $null) {

    if ( $last -match '[0-9]*s$' ) {

        [float]$last = $last -replace '[^0-9]',''

        $last = $last / 60

    } elseif ( $last -match '[0-9]*m$' ) {

        [int]$last = $last -replace '[^0-9]',''

    } elseif ( $last -match '[0-9]*h$' ) {

        [float]$last = $last -replace '[^0-9]',''

        $last = $last * 60

    } elseif ( $last -match '[0-9]*d$' ) {

        [float]$last = $last -replace '[^0-9]',''

        $last = $last * 1440

    }

    [DateTime]$starttime = ((Get-Date).AddMinutes(-$last))

} 

# Processing the provided computernames as arguments
if ($Computerlist) {
    
    $ComputerName = get-content -Path $Computerlist

}

# Pipe all computernames to run Get-Winevent parallel
@($ComputerName) | Start-RSJob -ScriptBlock {

        try {

            Get-WinEvent -Oldest -FilterHashTable @{path=$Using:path; Id=$Using:Id;starttime=$Using:starttime; endtime=$Using:endtime} -ComputerName $_ -ErrorAction Stop | 
        
                select MachineName, Id, TimeCreated, Message |

                where Message -match $Using:search |
            
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
        
                    DNSServer = $_.MachineName
                    Time = $_.TimeCreated
                    #Id = $_.Id
                    Source = $Source
                    Destination = $Destination
                    InterfaceIP = $InterfaceIP
                    QNAME = $QNAME
                    Port = $Port
                    Type = $Type
                } 
            } 
    
       } 
       
    catch [Exception] {

        if ($_.Exception -match "No events were found that match the specified selection criteria") {

            Write-Warning $_

            if (!$Using:last) {
                
                Write-Output "`nDid you run the script with arguments?`n`n.\DNS-tracer.ps1 -last 10m    #Display all DNS-events of last 10 minutes"

            } 

        } elseif ($_.Exception -match "The RPC server is unavailable") {
        
            Write-Warning "$Using:ComputerName - $_" 
    
        } else {

            Write-Warning $_

        }
    } 

} | Wait-RSJob | Receive-RSJob
