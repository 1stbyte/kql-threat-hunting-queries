# UAC Bypass Elevated Binary Execution Detection

Behavioral detection identifying execution of Windows auto-elevated binaries commonly abused to bypass User Account Control (UAC) and gain elevated privileges without triggering standard elevation prompts.

## Purpose

Detects execution of known Windows auto-elevated binaries frequently leveraged by attackers to bypass User Account Control protections and escalate privileges on compromised systems.

Monitoring these binaries helps identify early privilege escalation activity that may lead to persistence establishment, defense evasion, or lateral movement preparation.

## Telemetry Source

Microsoft Defender Advanced Hunting

Table:

DeviceProcessEvents

## Detection Logic

Identifies execution of known auto-elevated Windows binaries including:

- fodhelper.exe
- sdclt.exe
- eventvwr.exe
- computerdefaults.exe

Flags executions when launched by suspicious parent processes such as:

- powershell.exe
- cmd.exe
- wscript.exe
- cscript.exe
- mshta.exe
- rundll32.exe

Execution from script interpreters or LOLBins may indicate attempted privilege escalation activity.

## Detection Strategy

Attackers frequently abuse trusted Windows auto-elevated binaries to execute commands with elevated privileges while bypassing standard UAC prompts.

Monitoring parent-child process relationships involving these binaries helps identify abnormal privilege escalation behavior early in the attack lifecycle.

Unexpected execution chains involving scripting engines launching elevation-capable binaries should be treated as suspicious.

## MITRE ATT&CK Mapping

Tactic:

Privilege Escalation

Technique:

Abuse Elevation Control Mechanism (T1548)

## Analyst Investigation Guidance

Investigate:

- initiating parent process legitimacy
- command-line arguments passed during execution
- user execution context
- execution timing relative to login activity
- additional suspicious processes spawned afterward
- registry modification activity associated with UAC bypass techniques
- persistence or defense evasion activity following elevation

Executions originating from scripting engines or user-writable directories should be prioritized for investigation.

## Detection Tuning Recommendations

Detection fidelity can be improved by:

- excluding known enterprise management tooling activity
- correlating with registry modification telemetry
- monitoring abnormal parent-child execution relationships
- reviewing execution outside normal administrative workflows
- identifying elevation activity occurring shortly after phishing or initial access alerts

Environment-specific tuning helps reduce false positives and improves detection accuracy.

## False Positive Considerations

Legitimate administrative tools and enterprise management platforms may execute auto-elevated binaries during normal system configuration 
or maintenance workflows. Analysts should validate execution context and expected administrative activity before escalation.
