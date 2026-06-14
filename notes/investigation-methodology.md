\# SOC Investigation Methodology



&#x20;Objective



This document explains the investigation methodology followed in the Splunk SOC Log Analysis project. The goal is to demonstrate how a SOC analyst approaches alerts, validates evidence, builds timelines, extracts IOCs, and documents findings.



\---



\## SOC Investigation Workflow



\### 1. Identify the Alert



The first step is to understand what triggered the alert.



Key details to identify:



\* Alert name

\* Event type

\* Event code

\* Affected user

\* Source IP

\* Destination IP/domain

\* Process involved

\* Timestamp

\* Severity

\* Description



\---



\### 2. Validate the Evidence



After identifying the alert, the next step is to validate whether the activity is suspicious or expected.



Validation includes checking:



\* Repeated failed logins

\* Successful login after failed attempts

\* Suspicious parent-child process relationship

\* Encoded PowerShell commands

\* Outbound connections to suspicious IPs

\* Suspicious DNS queries

\* New account creation

\* Privileged group modification

\* Audit log clearing



\---



\### 3. Build the Timeline



A timeline helps understand the sequence of events.



Example:



1\. Failed login attempts

2\. Successful login

3\. Special privileges assigned

4\. Encoded PowerShell execution

5\. Outbound network connection

6\. Suspicious executable creation

7\. DNS query

8\. New user account creation

9\. Privileged group modification

10\. Audit log clearing



A timeline helps identify whether events are isolated or part of a larger attack chain.



\---



\### 4. Classify the Activity



After reviewing the evidence, classify the alert as:



\* False positive

\* True positive

\* Benign but suspicious

\* Needs escalation

\* Needs containment



A SOC analyst should not close an alert without evidence.



\---



\### 5. Extract Indicators of Compromise



Indicators of Compromise are evidence that may suggest malicious activity.



Examples from this project:



| IOC Type           | Example                    |

| ------------------ | -------------------------- |

| Source IP          | 185.44.76.10               |

| Suspicious IP      | 45.77.22.101               |

| Suspicious Domain  | malicious-update-check.com |

| Suspicious File    | invoice\_update.exe         |

| Suspicious Process | powershell.exe             |

| Parent Process     | WINWORD.EXE                |



\---



\### 6. Map to MITRE ATT\&CK



Mapping suspicious behavior to MITRE ATT\&CK helps explain attacker behavior.



Examples:



| Activity                      | MITRE Technique                           |

| ----------------------------- | ----------------------------------------- |

| Multiple failed logins        | T1110 — Brute Force                       |

| Encoded PowerShell            | T1059 — Command and Scripting Interpreter |

| New account creation          | T1136 — Create Account                    |

| Privileged group modification | T1098 — Account Manipulation              |

| Audit log clearing            | T1070 — Indicator Removal                 |



\---



\### 7. Recommend Actions



Recommended actions depend on the evidence and severity.



Examples:



\* Verify whether source IP is legitimate.

\* Confirm activity with the user.

\* Check MFA logs.

\* Reset password if compromise is suspected.

\* Block malicious IP/domain.

\* Quarantine suspicious file.

\* Investigate endpoint activity.

\* Escalate to L2 or Incident Response.

\* Preserve evidence.



\---



\### 8. Document the Case



Each investigation should include:



\* Alert title

\* Objective

\* Data source

\* SPL queries used

\* Findings

\* IOCs

\* MITRE mapping

\* Analyst assessment

\* Recommended actions

\* Conclusion



Good documentation helps SOC teams track incidents, escalate properly, and improve future detection.



\---



\## Final Methodology Summary



This project follows a SOC-style approach:



1\. Detect suspicious activity.

2\. Search logs in Splunk.

3\. Build timelines using SPL.

4\. Identify users, IPs, processes, and event codes.

5\. Extract IOCs.

6\. Map behavior to MITRE ATT\&CK.

7\. Write analyst-style reports.

8\. Recommend response actions.



