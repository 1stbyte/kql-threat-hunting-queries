# EDR Killer Service Tampering Detection

Behavioral detection identifying attempts to stop or disable endpoint security services using built-in Windows administration utilities commonly abused by ransomware operators during early defense-evasion preparation stages prior to payload execution.

---

## Detection Logic

This query analyzes Microsoft Defender endpoint process telemetry to identify:

- script interpreters launching service-control utilities
- execution of taskkill.exe, sc.exe, and net.exe
- command-line arguments indicating service termination activity
- targeting of Microsoft Defender and third-party endpoint protection platforms

Attackers frequently attempt to disable security tooling before deploying ransomware in order to reduce visibility and prevent automated containment actions.

---

## MITRE ATT&CK Mapping

**Tactic:** Defense Evasion  
**Technique:** T1562.001 — Impair Defenses: Disable Security Tools

---

## Why This Detection Matters

Modern ransomware operators routinely attempt to disable endpoint protection services prior to encryption execution. These actions are designed to:

- reduce telemetry visibility
- bypass behavioral detections
- prevent automated containment responses
- allow uninterrupted payload deployment

Security service tampering activity often represents one of the final preparation stages before ransomware execution begins.

---

## Example Suspicious Indicators

Analysts should prioritize investigation when observing:

- PowerShell stopping Microsoft Defender services
- taskkill.exe terminating endpoint protection processes
- sc.exe modifying security service configurations
- net.exe stopping monitoring components
- multiple service-control commands executed in sequence

---

## Investigation Steps

Recommended triage workflow:

1. Identify targeted service names
2. Confirm whether administrative maintenance activity was expected
3. Review parent-child process relationships
4. Investigate additional defense-evasion behavior
5. Check for lateral movement indicators
6. Validate endpoint protection status following execution

---

## Data Source

Microsoft Defender Advanced Hunting

DeviceProcessEvents

---

## Detection Strategy

This behavioral detection focuses on identifying security tool interference using native Windows administration utilities, a technique commonly observed across ransomware intrusion playbooks during early defense-evasion preparation stages.
