\---



\## 4. `04-privilege-abuse-report.md`



```md

\# Privilege Abuse and Audit Log Clearing Report



\## Alert Title

Suspicious Privilege Activity and Audit Log Clearing



\## Objective

To investigate account creation, privileged group modification, special privilege assignment, and audit log clearing activity.



\## Data Source

Splunk-ingested SOC sample logs.



\## Relevant Event Codes

\- 4672 — Special privileges assigned

\- 4720 — New user account created

\- 4728 — User added to privileged group

\- 1102 — Audit log cleared



\## SPL Query 1 — Account-Related Events



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" event\_type=account

| table \_time, EventCode, user, src\_ip, severity, description

| sort \_time

Finding 1 — Account Activity

Time	EventCode	User	Source IP	Description

10:32:00	4720	admin	10.0.0.5	New user account created

10:33:00	4728	admin	10.0.0.5	User added to privileged group

SPL Query 2 — Privileged Activity

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (EventCode=4672 OR EventCode=4720 OR EventCode=4728)

| table \_time, EventCode, user, src\_ip, severity, description

| sort \_time

Finding 2 — Privilege Activity

Time	EventCode	User	Source IP	Description

10:03:20	4672	ansh	185.44.76.10	Special privileges assigned

10:32:00	4720	admin	10.0.0.5	New user account created

10:33:00	4728	admin	10.0.0.5	User added to privileged group

SPL Query 3 — Audit Log Clearing

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=1102

| table \_time, EventCode, user, src\_ip, severity, description

| sort \_time

Finding 3 — Audit Log Cleared

Time	EventCode	User	Source IP	Severity	Description

10:40:00	1102	admin	10.0.0.5	critical	Audit log cleared

SPL Query 4 — Full Account Abuse Timeline

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (EventCode=4624 OR EventCode=4672 OR EventCode=4720 OR EventCode=4728 OR EventCode=1102)

| table \_time, event\_type, EventCode, user, src\_ip, severity, description

| sort \_time

Timeline of Activity

Time	EventCode	User	Source IP	Description

10:02:50	4624	ansh	185.44.76.10	Successful login after multiple failures

10:03:20	4672	ansh	185.44.76.10	Special privileges assigned

10:30:00	4624	admin	10.0.0.5	Normal admin login

10:32:00	4720	admin	10.0.0.5	New user account created

10:33:00	4728	admin	10.0.0.5	User added to privileged group

10:40:00	1102	admin	10.0.0.5	Audit log cleared

MITRE ATT\&CK Mapping

T1136 — Create Account

T1098 — Account Manipulation

T1070 — Indicator Removal

Analyst Assessment



The activity is suspicious because privilege-related events and audit log clearing were observed. New account creation and privileged group modification may indicate persistence or privilege abuse. Audit log clearing may indicate defense evasion.



Recommended Actions

Verify whether account creation was authorized.

Check change management/ticket records.

Review admin account activity.

Confirm whether privileged group modification was legitimate.

Investigate audit log clearing.

Check for lateral movement or persistence.

Escalate if actions were unauthorized.

Conclusion



This case demonstrates detection of possible privilege abuse and defense evasion using Splunk. The activity requires validation against approved administrative activity before closure.

