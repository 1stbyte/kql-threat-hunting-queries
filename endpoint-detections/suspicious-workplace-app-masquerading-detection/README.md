# Suspicious Workplace App Masquerading Detection

Behavioral detection identifying workplace productivity application names executing from non-standard file paths that may indicate masquerading or signed malware abuse.

## Purpose

Detects execution of commonly trusted workplace applications running outside expected installation directories such as Program Files or Windows system paths. Attackers frequently disguise malicious binaries using legitimate application names to evade detection and blend into normal enterprise activity.

Monitoring trusted application names executing from unusual locations helps identify potential masquerading activity and early-stage compromise indicators.

## Telemetry Source

Microsoft Defender Advanced Hunting

Table:

DeviceProcessEvents

## Detection Logic

Identifies execution of commonly trusted workplace applications including:

- msteams.exe
- teams.exe
- slack.exe
- zoom.exe
- webex.exe
- onedrive.exe
- googledrivefs.exe
- dropbox.exe
- box.exe
- teamviewer.exe
- screenconnect.clientservice.exe
- connectwisecontrol.client.exe

Flags executions occurring outside expected directories such as:

- C:\Program Files
- C:\Program Files (x86)
- C:\Windows

Execution from alternate locations may indicate:

- masquerading behavior
- signed malware abuse
- unauthorized remote management tool deployment
- persistence mechanisms
- attacker staging activity

## Detection Strategy

Attackers frequently rename malicious binaries to resemble trusted enterprise applications in order to bypass security controls and 
reduce analyst suspicion. Monitoring execution paths for trusted application names helps detect this behavior early in the attack lifecycle.
Unexpected execution of workplace applications from user-writable directories should be treated as suspicious.

## MITRE ATT&CK Mapping

Tactic:

Defense Evasion

Technique:

Masquerading (T1036)

## Analyst Investigation Guidance

Investigate:

- execution directory legitimacy
- command-line arguments
- parent-child process lineage
- initiating user context
- execution timing patterns
- presence on additional endpoints
- follow-on suspicious activity from the host

Executions from user-writable directories such as AppData, Temp, Public, or Downloads should be prioritized for investigation.

## Detection Tuning Recommendations

Detection fidelity can be improved by:

- restricting detections to after-hours execution windows
- excluding known enterprise deployment paths
- correlating with suspicious parent process execution
- reviewing unsigned binaries using trusted application names
- identifying execution originating from user profile directories

Environment-specific tuning helps reduce false positives and improves detection accuracy.

## False Positive Considerations

Legitimate enterprise software deployment tools or portable application usage may occasionally execute trusted 
binaries from alternate locations. Analysts should validate execution context and user intent before escalation.
