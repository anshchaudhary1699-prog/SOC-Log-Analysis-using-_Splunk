\# MITRE ATT\&CK Mapping



\## Objective



This document maps the suspicious activity detected in the Splunk SOC Log Analysis project to relevant MITRE ATT\&CK techniques.



MITRE ATT\&CK is used by SOC teams to categorize attacker behavior and improve investigation context.



\---



\## Case Study 1: Brute Force Login Detection



\### Observed Behavior



Multiple failed login attempts were observed for user `ansh` from source IP `185.44.76.10`, followed by a successful login.



\### MITRE Mapping



| Tactic            | Technique   | ID    | Description                                                                         |

| ----------------- | ----------- | ----- | ----------------------------------------------------------------------------------- |

| Credential Access | Brute Force | T1110 | Adversaries may attempt to guess valid credentials through repeated login attempts. |



\### Reason for Mapping



The activity shows repeated failed authentication attempts followed by successful authentication, which may indicate brute-force activity or credential compromise.



\---



\## Case Study 2: Suspicious PowerShell Execution



\### Observed Behavior



PowerShell was launched by `WINWORD.EXE` using an encoded command:



```text

powershell.exe -enc SQBFAFgA

```



\### MITRE Mapping



| Tactic              | Technique                         | ID    | Description                                                                             |

| ------------------- | --------------------------------- | ----- | --------------------------------------------------------------------------------------- |

| Execution           | Command and Scripting Interpreter | T1059 | Adversaries may abuse command-line interpreters such as PowerShell to execute commands. |

| Execution           | User Execution                    | T1204 | Adversaries may rely on user interaction such as opening a malicious document.          |

| Command and Control | Ingress Tool Transfer             | T1105 | Adversaries may transfer tools or payloads into a compromised environment.              |



\### Reason for Mapping



Microsoft Word launching PowerShell is suspicious because Office applications are commonly abused in phishing or macro-based attacks. Encoded PowerShell is often used to hide command intent.



\---



\## Case Study 3: Malware IOC and Network Connection



\### Observed Behavior



PowerShell connected to suspicious IP `45.77.22.101`, created suspicious executable `invoice\_update.exe`, and queried domain `malicious-update-check.com`.



\### MITRE Mapping



| Tactic              | Technique                         | ID    | Description                                                           |

| ------------------- | --------------------------------- | ----- | --------------------------------------------------------------------- |

| Execution           | Command and Scripting Interpreter | T1059 | PowerShell was used to execute commands.                              |

| Command and Control | Application Layer Protocol        | T1071 | Adversaries may communicate using common application layer protocols. |

| Command and Control | Ingress Tool Transfer             | T1105 | Suspicious executable activity may indicate payload transfer.         |



\### Reason for Mapping



The activity shows a possible malware execution chain involving PowerShell, outbound communication, suspicious file creation, and DNS activity.



\---



\## Case Study 4: Privilege Abuse and Audit Log Clearing



\### Observed Behavior



The logs showed:



\* Special privileges assigned

\* New user account created

\* User added to privileged group

\* Audit log cleared



\### MITRE Mapping



| Tactic                             | Technique            | ID    | Description                                                       |

| ---------------------------------- | -------------------- | ----- | ----------------------------------------------------------------- |

| Persistence                        | Create Account       | T1136 | Adversaries may create accounts to maintain access.               |

| Persistence / Privilege Escalation | Account Manipulation | T1098 | Adversaries may modify accounts or groups to maintain privileges. |

| Defense Evasion                    | Indicator Removal    | T1070 | Adversaries may delete or clear logs to hide activity.            |



\### Reason for Mapping



Account creation and privileged group modification can indicate persistence or privilege abuse. Audit log clearing may indicate defense evasion.



\---



\## Summary Table



| Case Study                  | Suspicious Activity                        | MITRE Technique                           |

| --------------------------- | ------------------------------------------ | ----------------------------------------- |

| Brute Force Login Detection | Multiple failed logins followed by success | T1110 — Brute Force                       |

| Suspicious PowerShell       | Encoded PowerShell launched by Word        | T1059 — Command and Scripting Interpreter |

| Suspicious PowerShell       | User likely opened malicious document      | T1204 — User Execution                    |

| Malware IOC                 | Suspicious external communication          | T1071 — Application Layer Protocol        |

| Malware IOC                 | Possible payload transfer                  | T1105 — Ingress Tool Transfer             |

| Privilege Abuse             | New account created                        | T1136 — Create Account                    |

| Privilege Abuse             | User added to privileged group             | T1098 — Account Manipulation              |

| Log Clearing                | Audit log cleared                          | T1070 — Indicator Removal                 |



\---



\## Final Note



MITRE ATT\&CK mapping helps explain what attacker behavior may be represented by the logs. Mapping does not prove compromise by itself; it adds investigation context and supports analyst reporting.



