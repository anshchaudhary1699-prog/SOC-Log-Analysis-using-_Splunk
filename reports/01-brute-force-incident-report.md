\# Brute Force Login Detection Report



\## Alert Title

Multiple Failed Login Attempts Followed by Successful Login

1. 01-brute-force-incident-report.md

\## Objective

To investigate repeated failed login attempts from the same source IP followed by a successful login, which may indicate brute-force activity or credential compromise.



\## Data Source

Splunk-ingested SOC sample logs.



\## Relevant Event Codes

\- 4625 — Failed login attempt

\- 4624 — Successful login

\- 4672 — Special privileges assigned



\## SPL Query 1 — Failed Login Count



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=4625

| stats count as failed\_attempts by user, src\_ip, host

| sort -failed\_attempts
Finding 1

The search identified repeated failed login attempts for the same user from the same source IP.

Field	Value
User	ansh
Source IP	185.44.76.10
Host	CYSEC
Failed Attempts	4
SPL Query 2 — Authentication Timeline
source="_time,event_type,EventCode,host,use.txt" sourcetype="csv" (EventCode=4625 OR EventCode=4624)
| table _time, EventCode, host, user, src_ip, severity, description
| sort _time
Finding 2

The authentication timeline showed multiple failed login attempts followed by a successful login.

Time	EventCode	User	Source IP	Description
10:01:00	4625	ansh	185.44.76.10	Failed login attempt
10:01:15	4625	ansh	185.44.76.10	Failed login attempt
10:01:32	4625	ansh	185.44.76.10	Failed login attempt
10:02:10	4625	ansh	185.44.76.10	Failed login attempt
10:02:50	4624	ansh	185.44.76.10	Successful login after multiple failures
MITRE ATT&CK Mapping
T1110 — Brute Force
Analyst Assessment

The activity is suspicious because repeated failed login attempts were followed by a successful login from the same source IP. This may indicate brute-force activity or possible credential compromise.

Recommended Actions
Verify whether the source IP is trusted.
Confirm with the user whether the login was legitimate.
Check post-login activity for privilege use or lateral movement.
Review MFA status.
Reset password and revoke sessions if compromise is suspected.
Escalate to L2/Incident Response if unauthorized access is confirmed.
Conclusion

This case demonstrates a possible brute-force login pattern. The evidence supports further investigation before closing the alert.


