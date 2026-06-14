

\---



\## 2. `02-suspicious-powershell-report.md`



```md

\# Suspicious PowerShell Execution Report



\## Alert Title

Encoded PowerShell Execution Launched by Microsoft Word



\## Objective

To investigate suspicious PowerShell execution where Microsoft Word launched PowerShell with an encoded command.



\## Data Source

Splunk-ingested SOC sample logs.



\## Relevant Event Codes

\- 1 — Process creation

\- 3 — Network connection

\- 11 — File creation

\- 22 — DNS query



\## SPL Query 1 — Process Events



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" event\_type=process

| table \_time, EventCode, host, user, process, parent\_process, command, severity, description

| sort \_time

SPL Query 2 — PowerShell Execution

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" process="powershell.exe"

| table \_time, host, user, process, parent\_process, command, severity, description

| sort \_time

SPL Query 3 — Encoded PowerShell

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" command="\*-enc\*"

| table \_time, host, user, process, parent\_process, command, severity, description

| sort \_time

Key Finding



PowerShell was launched by Microsoft Word using an encoded command.



Field	Value

User	employee1

Process	powershell.exe

Parent Process	WINWORD.EXE

Command	powershell.exe -enc SQBFAFgA

Severity	high

SPL Query 4 — Full PowerShell Timeline

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" user="employee1"

| table \_time, event\_type, EventCode, user, process, parent\_process, command, dest\_ip, severity, description

| sort \_time

Timeline of Activity

Time	Event Type	Process	Description

10:10:00	process	powershell.exe	Encoded PowerShell launched by Word

10:10:20	network	powershell.exe	PowerShell outbound connection to suspicious IP

10:11:00	file	invoice\_update.exe	Suspicious executable created in temp directory

10:12:00	dns	powershell.exe	Suspicious DNS query

MITRE ATT\&CK Mapping

T1059 — Command and Scripting Interpreter

T1204 — User Execution

T1105 — Ingress Tool Transfer

Analyst Assessment



The activity is suspicious because Microsoft Word launched PowerShell with an encoded command. This behavior is commonly associated with phishing attachments, malicious macros, script-based payload execution, or post-exploitation activity.



Recommended Actions

Validate whether the Word document was expected.

Decode and analyze the PowerShell command if possible.

Check whether the user opened a suspicious email attachment.

Investigate outbound connection to 45.77.22.101.

Check for created file invoice\_update.exe.

Isolate endpoint if malicious execution is confirmed.

Escalate to L2/Incident Response.

Conclusion



This case demonstrates a suspicious PowerShell execution chain that may indicate phishing-based malware execution or command-and-control activity.

