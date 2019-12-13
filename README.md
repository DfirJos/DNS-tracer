# DNS-tracer
This PowerShell script helps analysts track down internal endpoints that are querying (for example) malicious domains. It can be hard for analysts to track these endpoints solely based on an alert, especially when there is no proper set-up in place that can help with this. It is not uncommon that the triggered alert states the Source IP address of the DNS-server as the culprit that is querying malicious domains, while actually the true source is an endpoint behind the DNS-server. 

See blogpost for a more extended description: https://infosecfailu.re/2019/12/01/tracing-the-source-of-internal-dns-requests-with-microsoft-event-trace-log-etl-files/

## Prerequisites

At least Server 2012 R2 is required to enable the necessary feature that logs DNS events to ETL files.

1) On Server 2012, check if you have the required hotfix installed

```
wmic qfe | find "KB2956577”
```
If not installed, you have to install it and reboot your server. An "How To" is provided here: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn800669(v%3Dws.11)

2) Enable Enhanced DNS Logging and Diagnostics (see above URL)

3) If you want to query remote computers, you can choose if you want to use PowerShell remoting or RPC/TCP.

Configure PowerShell remoting 

Open proper ports on DNS-server for querying Event Log service with RPC/TCP, whereas the IP address points to the system where this script will be launched on:

```
Get-NetFirewallRule | where DisplayName -like  '*Event Log*' | Enable-NetFirewallRule | Set-NetFireWallRule -RemoteAddress 192.168.2.240
```

## Quick start

Display DNS events on the local computer of the last 2 days (default value).
```
DNS-tracer.ps1
```

Display all DNS events of the last 100 minutes on multiple servers:
```
DNS-tracer.ps1 -ComputerName dc01, dns01 -last 100m
```

It also works with a list of computernames
```
DNS-tracer.ps1 -ComputerList D:\computernames.txt
```

Display all DNS events in the last 2 minutes regarding 'example':

```
DNS-tracer.ps1 -ComputerName dc01, dns01 -last 2m -search 'example'
```

![Image](/Images/Example.png)

Display DNS events related to 'example.com' in the given timeperiod:
```
DNS-tracer.ps1 -starttime "11/21/2019 12:41 AM" -endtime "11/21/2019 12:50 AM" -search example.com 
```

Run the task with PowerShell remoting in a parallel fashion. Default setting is that it runs the task of querying DNS events sequentially, it queries the remote computers over RPC/TCP.
```
DNS-tracer.ps1 -ComputerList D:\computernames.txt -WinRM
```


