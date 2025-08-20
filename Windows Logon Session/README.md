

# Sysinternals - Logonsessions 
> If you think that when you logon to a system there's only one active logon session, this utility will surprise you. It lists the currently active logon sessions and, if you specify the -p option, the processes running in each session.

## Description

[Sysinternals Logonsessions - Official documentation.](https://docs.microsoft.com/en-us/sysinternals/downloads/logonsessions)

## Wazuh Integration

Wazuh Capability: Wodles Command

Log Output: Active Response Log

MITRE: T1078

Edit agent configuration in Wazuh manager (shared/groups)

(/var/ossec/etc/shared/your_windows_agents_group/agent.conf)

 ```<wodle name="command">
  <disabled>no</disabled>
  <tag>logonsessions</tag>
  <command>Powershell.exe -executionpolicy bypass -File "C:\Program Files\Sysinternals\logonsessions.ps1"</command>
  <interval>1h</interval>
  <ignore_output>yes</ignore_output>
  <run_on_start>yes</run_on_start>
  <timeout>0</timeout>
</wodle>
```
File “logonsessions.ps1”:

```################################
################################
##########
# Script execution triggered by Wazuh Manager, wodles-command
# Output converted to JSON and appended to active-responses.log
##########
# RUN LOGONSESSIONS AND STORE CSV
$Sessions_Output_CSV = c:\"Program Files"\Sysinternals\logonsessions.exe  -nobanner -c -p
# REMOVE SPACES IN CSV HEADER AND CONVERT TO ARRAY
$Sessions_Output_Array = $Sessions_Output_CSV.PSObject.BaseObject.Trim(' ') -Replace '\s','' | ConvertFrom-Csv
# GO THRU THE ARRAY, CONVERT TO JSON AND APPEND TO active-responses.log
Foreach ($item in $Sessions_Output_Array) {
  echo  $item | ConvertTo-Json -Compress | Out-File -width 2000 C:\"Program Files (x86)"\ossec-agent\active-response\active-responses.log -Append -Encoding ascii
 }
```
