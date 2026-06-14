\# Splunk Basics for SOC Investigation



\## What is Splunk?



Splunk is a platform used to collect, index, search, analyze, visualize, and alert on machine-generated data.



In a SOC environment, Splunk is used for:



\* Log analysis

\* Alert triage

\* Incident investigation

\* Threat detection

\* Dashboard creation

\* IOC searching

\* Security monitoring



\---



\## Key Splunk Terms



\### Event



A single log entry.



\### Index



A storage location where Splunk stores events.



Example:



```spl

index=soc\_lab

```



\### Sourcetype



Defines the type or format of the log data.



Example:



```spl

sourcetype="csv"

```



\### Source



The origin of the log data, such as a file name.



Example:



```spl

source="\_time,event\_type,EventCode,host,use.txt"

```



\### Host



The system or device associated with the event.



\### Field



A searchable key-value pair extracted from logs.



Examples:



\* EventCode

\* user

\* src\_ip

\* dest\_ip

\* process

\* severity

\* description



\---



\## Common SPL Commands Used



\### table



Displays selected fields.



```spl

| table \_time, EventCode, user, src\_ip, description

```



\### stats



Aggregates data.



```spl

| stats count by user, src\_ip

```



\### sort



Sorts results.



```spl

| sort \_time

```



```spl

| sort -failed\_attempts

```



\### where



Filters results after calculation.



```spl

| where failed\_attempts > 5

```



\### eval



Creates or modifies fields.



```spl

| eval status=if(EventCode=4625,"Failed Login","Other")

```



\---



\## Important Event Codes Used in This Project



| Event Code | Description                    |

| ---------- | ------------------------------ |

| 4625       | Failed login attempt           |

| 4624       | Successful login               |

| 4672       | Special privileges assigned    |

| 4720       | New user account created       |

| 4728       | User added to privileged group |

| 1102       | Audit log cleared              |

| 1          | Process creation               |

| 3          | Network connection             |

| 11         | File creation                  |

| 22         | DNS query                      |



\---



\## Basic Search Examples



\### Search all project logs



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv"

```



\### Search failed logins



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=4625

```



\### Search successful logins



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=4624

```



\### Search suspicious PowerShell



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" process="powershell.exe"

```



\### Search encoded PowerShell



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" command="\*-enc\*"

```



\### Search network events



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" event\_type=network

```



\### Search DNS events



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" event\_type=dns

```



\---



\## SOC Use Cases Covered



\### 1. Brute Force Detection



Query:



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=4625

| stats count as failed\_attempts by user, src\_ip

| sort -failed\_attempts

```



Purpose:



Detect repeated failed login attempts from the same user/source IP.



\---



\### 2. Suspicious PowerShell Detection



Query:



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" command="\*-enc\*"

| table \_time, user, process, parent\_process, command, severity, description

| sort \_time

```



Purpose:



Detect encoded PowerShell execution, which may indicate obfuscation or malicious script execution.



\---



\### 3. Malware IOC Investigation



Query:



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (dest\_ip="45.77.22.101" OR dest\_ip="malicious-update-check.com" OR process="invoice\_update.exe" OR process="powershell.exe")

| table \_time, event\_type, EventCode, user, process, parent\_process, command, dest\_ip, severity, description

| sort \_time

```



Purpose:



Build a timeline of suspicious PowerShell activity, network connection, file creation, and DNS query.



\---



\### 4. Privilege Abuse Investigation



Query:



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (EventCode=4672 OR EventCode=4720 OR EventCode=4728 OR EventCode=1102)

| table \_time, EventCode, user, src\_ip, severity, description

| sort \_time

```



Purpose:



Detect privileged activity, account creation, privileged group modification, and audit log clearing.



\---



\## Dashboard Panels Created



The project dashboard includes:



1\. Brute Force Failed Login Count

2\. Authentication and Privilege Abuse Timeline

3\. Suspicious PowerShell Execution Timeline

4\. Suspicious Network IOC Connections

5\. Event Severity Summary

6\. Critical Security Events



Dashboard title:



```text

SOC Investigation Overview

```



\---



\## Key Learning Outcomes



This project helped demonstrate:



\* Log ingestion in Splunk

\* SPL query writing

\* Authentication log analysis

\* PowerShell investigation

\* IOC extraction

\* DNS investigation

\* Privilege abuse detection

\* Audit log clearing detection

\* Dashboard creation

\* SOC-style documentation



\---



\## Final Note



Splunk is not just a search tool. In SOC operations, it helps analysts collect evidence, validate alerts, build timelines, correlate activity, and document incidents for escalation or closure.



