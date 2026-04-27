# Privilege Enumeration and Suspicious Staging Detection
Behavioral detection identifying privilege enumeration commands and executable staging activity from user-writable directories that may indicate preparation for privilege escalation.

## Purpose
Detects execution of privilege enumeration commands such as **whoami /priv** alongside process execution from user-writable directories commonly used by attackers to stage payloads prior to privilege escalation attempts.
Monitoring privilege discovery behavior combined with suspicious staging locations helps identify attacker reconnaissance activity early in the privilege escalation phase of an intrusion.

## Telemetry Source
Microsoft Defender Advanced Hunting

Table:
DeviceProcessEvents

## Detection Logic
Identifies execution of privilege enumeration commands including:

- whoami /priv
- whoami.exe /priv

Also detects processes executing from common staging locations such as:
- Downloads
- Pictures
- AppData
- Public user directories
- ProgramData

Execution from these directories may indicate:
- privilege escalation preparation
- payload staging behavior
- attacker reconnaissance activity
- post-compromise environment discovery
- preparation for persistence or lateral movement

## Detection Strategy
Attackers frequently perform privilege enumeration after gaining initial access to determine whether administrative privileges or escalation paths are available.
Commands such as **whoami /priv** are commonly used to inspect token privileges and evaluate potential escalation opportunities.
Execution of binaries from user-writable directories shortly before or after privilege enumeration activity may indicate staging behavior associated with escalation attempts.
Monitoring both behaviors together improves detection fidelity and provides visibility into attacker preparation activity.

## MITRE ATT&CK Mapping

Tactic:
Privilege Escalation

Technique:
Exploitation for Privilege Escalation (T1068)
Related Technique:
Account Discovery (T1087)

## Analyst Investigation Guidance

Investigate:
- legitimacy of the executing user context
- parent process initiating privilege enumeration
- command-line arguments associated with execution
- execution timing relative to login activity
- additional suspicious processes launched afterward
- presence of newly staged executables in user-writable directories
- follow-on persistence or defense evasion behavior

Privilege enumeration activity combined with suspicious staging paths should be prioritized for investigation.

## Detection Tuning Recommendations

Detection fidelity can be improved by:
- correlating with suspicious parent processes such as PowerShell or script interpreters
- excluding known administrative automation activity
- identifying repeated enumeration attempts across multiple endpoints
- monitoring execution shortly after phishing or initial access alerts
- correlating with registry modification or service creation activity

Environment-specific tuning helps reduce false positives and improves detection accuracy.

## False Positive Considerations

System administrators and automation tools may legitimately execute privilege enumeration commands during troubleshooting or configuration workflows. Analysts should validate execution context and expected administrative behavior before escalation.
