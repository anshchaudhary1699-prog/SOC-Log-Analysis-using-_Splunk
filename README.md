\# SOC Log Analysis using Splunk



\## Project Overview



This project demonstrates a SOC analyst-style investigation using Splunk. The objective is to analyze security logs, detect suspicious activity, investigate potential incidents, extract indicators of compromise, map findings to MITRE ATT\&CK, and document results in an incident-report format.



The project covers multiple common SOC use cases:



1\. Brute-force login detection

2\. Suspicious PowerShell execution

3\. Malware IOC and suspicious network connection investigation

4\. Privilege abuse and audit log clearing

5\. SOC investigation dashboard creation



This project is designed to demonstrate beginner-to-intermediate SOC investigation skills using Splunk SPL, Windows-style event logs, Sysmon-style event patterns, and structured analyst reporting.



\---



\## Tools Used



\* Splunk Enterprise

\* SPL — Search Processing Language

\* Windows Security Event Log concepts

\* Sysmon-style event concepts

\* MITRE ATT\&CK Framework

\* GitHub

\* Markdown documentation



\---



\## Dataset



A custom SOC sample dataset was created and ingested into Splunk. The dataset includes simulated security events related to:



\* Failed login attempts

\* Successful login after multiple failures

\* Special privilege assignment

\* Encoded PowerShell execution

\* PowerShell outbound connection

\* Suspicious executable creation

\* Suspicious DNS query

\* New user account creation

\* Privileged group modification

\* Audit log clearing



Dataset location:



```text

dataset/soc\_sample\_logs.csv

```



\---



\## Repository Structure



```text

SOC-Log-Analysis-using-Splunk/

│

├── README.md

│

├── dataset/

│   └── soc\_sample\_logs.csv

│

├── spl-queries/

│   ├── 01-brute-force-detection.spl

│   ├── 02-suspicious-powershell.spl

│   ├── 03-malware-ioc-investigation.spl

│   ├── 04-privilege-abuse-investigation.spl

│   └── 05-dashboard-panels.spl

│

├── reports/

│   ├── 01-brute-force-incident-report.md

│   ├── 02-suspicious-powershell-report.md

│   ├── 03-malware-ioc-report.md

│   └── 04-privilege-abuse-report.md

│

├── screenshots/

│   ├── brute-force-failed-login-count.png

│   ├── brute-force-login-timeline.png

│   ├── powershell-process-execution.png

│   ├── powershell-encoded-command.png

│   ├── powershell-network-connection.png

│   ├── powershell-investigation-timeline.png

│   ├── network-ioc-events.png

│   ├── suspicious-ip-count.png

│   ├── suspicious-dns-query.png

│   ├── malware-ioc-investigation-timeline.png

│   ├── account-abuse-events.png

│   ├── privilege-activity-investigation.png

│   ├── audit-log-cleared.png

│   ├── account-abuse-full-timeline.png

│   └── dashboard-overview.png

│

└── notes/

&#x20;   ├── investigation-methodology.md

&#x20;   ├── mitre-mapping.md

&#x20;   └── splunk-basics.md

```



\---



\## Case Study 1: Brute Force Login Detection



\### Objective



To detect multiple failed login attempts from the same source IP followed by a successful login.



\### Relevant Event Codes



| Event Code | Description                 |

| ---------- | --------------------------- |

| 4625       | Failed login attempt        |

| 4624       | Successful login            |

| 4672       | Special privileges assigned |



\### SPL Query



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" EventCode=4625

| stats count as failed\_attempts by user, src\_ip, host

| sort -failed\_attempts

```



\### Finding



The user `ansh` had multiple failed login attempts from source IP `185.44.76.10`, followed by a successful login.



\### MITRE ATT\&CK Mapping



| Technique   | ID    |

| ----------- | ----- |

| Brute Force | T1110 |



\### Screenshot



```text

screenshots/brute-force-failed-login-count.png

```



\---



\## Case Study 2: Suspicious PowerShell Execution



\### Objective



To investigate PowerShell execution launched by Microsoft Word with an encoded command.



\### Relevant Event Codes



| Event Code | Description        |

| ---------- | ------------------ |

| 1          | Process creation   |

| 3          | Network connection |

| 11         | File creation      |

| 22         | DNS query          |



\### SPL Query



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" command="\*-enc\*"

| table \_time, host, user, process, parent\_process, command, severity, description

| sort \_time

```



\### Finding



PowerShell was launched by `WINWORD.EXE` with an encoded command:



```text

powershell.exe -enc SQBFAFgA

```



This behavior may indicate phishing attachment execution, macro abuse, or script-based malware activity.



\### MITRE ATT\&CK Mapping



| Technique                         | ID    |

| --------------------------------- | ----- |

| Command and Scripting Interpreter | T1059 |

| User Execution                    | T1204 |

| Ingress Tool Transfer             | T1105 |



\### Screenshot



```text

screenshots/powershell-investigation-timeline.png

```



\---



\## Case Study 3: Malware IOC and Suspicious Network Connection



\### Objective



To investigate suspicious outbound communication, DNS activity, and executable creation linked to PowerShell.



\### SPL Query



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (dest\_ip="45.77.22.101" OR dest\_ip="malicious-update-check.com" OR process="invoice\_update.exe" OR process="powershell.exe")

| table \_time, event\_type, EventCode, user, process, parent\_process, command, dest\_ip, severity, description

| sort \_time

```



\### Extracted IOCs



| IOC Type           | Value                      |

| ------------------ | -------------------------- |

| Suspicious IP      | 45.77.22.101               |

| Suspicious Domain  | malicious-update-check.com |

| Suspicious File    | invoice\_update.exe         |

| Suspicious Process | powershell.exe             |

| Parent Process     | WINWORD.EXE                |



\### Finding



The activity shows encoded PowerShell execution followed by outbound communication to a suspicious IP, suspicious executable creation, and DNS activity. This may indicate malware execution or command-and-control behavior.



\### MITRE ATT\&CK Mapping



| Technique                         | ID    |

| --------------------------------- | ----- |

| Command and Scripting Interpreter | T1059 |

| Ingress Tool Transfer             | T1105 |

| Application Layer Protocol        | T1071 |



\### Screenshot



```text

screenshots/malware-ioc-investigation-timeline.png

```



\---



\## Case Study 4: Privilege Abuse and Audit Log Clearing



\### Objective



To investigate account creation, privileged group modification, special privilege assignment, and audit log clearing activity.



\### Relevant Event Codes



| Event Code | Description                    |

| ---------- | ------------------------------ |

| 4672       | Special privileges assigned    |

| 4720       | New user account created       |

| 4728       | User added to privileged group |

| 1102       | Audit log cleared              |



\### SPL Query



```spl

source="\_time,event\_type,EventCode,host,use.txt" sourcetype="csv" (EventCode=4624 OR EventCode=4672 OR EventCode=4720 OR EventCode=4728 OR EventCode=1102)

| table \_time, event\_type, EventCode, user, src\_ip, severity, description

| sort \_time

```



\### Finding



The timeline shows successful login activity, special privilege assignment, new account creation, privileged group modification, and audit log clearing. This pattern may indicate privilege abuse, persistence setup, or defense evasion.



\### MITRE ATT\&CK Mapping



| Technique            | ID    |

| -------------------- | ----- |

| Create Account       | T1136 |

| Account Manipulation | T1098 |

| Indicator Removal    | T1070 |



\### Screenshot



```text

screenshots/account-abuse-full-timeline.png

```



\---



\## SOC Dashboard



A Splunk dashboard was created to summarize the investigation.



Dashboard title:



```text

SOC Investigation Overview

```



Dashboard panels include:



\* Brute Force Failed Login Count

\* Authentication and Privilege Abuse Timeline

\* Suspicious PowerShell Execution Timeline

\* Suspicious Network IOC Connections

\* Event Severity Summary

\* Critical Security Events



Dashboard screenshot:



```text

screenshots/dashboard-overview.png

```



\---



\## Key Skills Demonstrated



\* Splunk log ingestion

\* SPL query writing

\* SOC alert triage

\* Brute-force detection

\* Suspicious PowerShell investigation

\* Malware IOC extraction

\* DNS investigation

\* Privilege abuse detection

\* Audit log clearing detection

\* Incident documentation

\* MITRE ATT\&CK mapping

\* Dashboard creation

\* Analyst-style reporting



\---



\## Analyst Methodology



The investigation followed a SOC-style workflow:



1\. Identify suspicious activity.

2\. Validate logs and evidence.

3\. Build timelines using SPL.

4\. Extract IOCs.

5\. Map behavior to MITRE ATT\&CK.

6\. Assess severity and impact.

7\. Recommend containment or escalation.

8\. Document findings in incident reports.



\---



\## Limitations



This project uses a simulated SOC dataset for learning and portfolio demonstration. It does not represent a live enterprise SOC environment. However, the investigation workflow, SPL query logic, event interpretation, and reporting structure are aligned with real SOC analyst practices.



\---



\## Conclusion



This project demonstrates practical SOC investigation using Splunk. It covers authentication-based attacks, suspicious PowerShell execution, malware IOC investigation, privilege abuse detection, and audit log clearing. The project helped strengthen hands-on understanding of SIEM investigation, SPL queries, alert triage, IOC extraction, and incident reporting.



