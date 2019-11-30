# DNS-tracer
This script helps analysts to trace internal endpoints that are querying specific domains, such as the domain of a command and control center. It is not uncommon for analysts to only have an alert which states the Source IP address of the DNS-server as the culprit, while actually the culprit is an endpoint behind the DNS-server. This PowerShell script uses Microsoft Event Trace Log (ETL) files to trace the true origin.

## Prerequisites

At least Server 2012 R2 is required to enable the necessary feature that logs DNS events to ETL files.

1) On Server 2012, check if you have the required hotfix installed

```
wmic qfe | find "KB2956577”
```
If not installed, you have to install it and reboot your server. An "How To" is provided here: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v%3Dws.11)

2) Enable Enhanced DNS Logging and Diagnostics (see above URL)

## Quick start

Display all DNS events of the last 100 minutes on multiple servers:
```
DNS-tracer.ps1 -computer dc01, dns01 -last 100m
```
![Image](/Images/Example.png)

Display DNS events related to 'example.com' in the given timeperiod:
```
DNS-tracer.ps1 -starttime "11/21/2019 12:41 AM" -endtime "11/21/2019 12:50 AM" -search example.com 
```
