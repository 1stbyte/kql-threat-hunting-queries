
# EDR Tampering Attempts Detection

Behavioral detection identifying attempts to disable or interfere with endpoint security protections using Microsoft Defender Advanced Hunting telemetry.

## Purpose

Detects suspicious commands attempting to stop, disable, delete, or terminate endpoint protection services commonly targeted by attackers prior to lateral movement or ransomware deployment.

## Detection Scope

Monitors execution of administrative utilities commonly abused to tamper with endpoint detection and response (EDR) tooling across Windows endpoints using DeviceProcessEvents telemetry.

## Telemetry Source

Microsoft Defender Advanced Hunting

Table:
DeviceProcessEvents

## Detection Logic

Identifies execution of administrative utilities commonly used to tamper with security controls including:

- sc.exe
- taskkill.exe
- net.exe
- powershell.exe
- cmd.exe

Flags command-line activity referencing endpoint protection services such as:

- WinDefend
- Sense
- MsMpEng
- SecurityHealthService
- CrowdStrike
- CarbonBlack
- SentinelOne
- Sophos
- Symantec
- TrendMicro

Also detects keywords associated with service tampering behavior:

- stop
- disable
- delete
- terminate
- kill

## Detection Strategy

Attackers frequently attempt to disable endpoint detection and response (EDR) tooling before executing follow-on activity such as credential access, 
lateral movement, or ransomware deployment. Monitoring service-termination commands targeting security tooling provides early visibility into defense-evasion 
behavior.

## MITRE ATT&CK Mapping

Tactic:
Defense Evasion

Technique:
Impair Defenses (T1562.001)

## Analyst Investigation Guidance

Investigate:

- initiating parent process
- execution context and privilege level
- command-line arguments
- targeted security service name
- additional follow-on suspicious activity on the host

Unexpected attempts to disable endpoint security tooling are strong indicators of malicious intent and should be prioritized for investigation.
