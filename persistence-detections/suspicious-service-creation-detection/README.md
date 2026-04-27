# Suspicious Service Creation Detection

Behavioral detection identifying creation of new Windows services that may indicate persistence establishment by an attacker.

## Purpose

Detects creation of new Windows services which attackers commonly use to maintain persistence on compromised systems. Malicious services allow adversaries to execute code automatically during system startup or maintain long-term access to a host.

Monitoring service creation activity provides early visibility into persistence techniques used prior to privilege escalation, lateral movement, or ransomware staging activity.

## Telemetry Source

Windows Security Logs / Microsoft Sentinel

Table:

SecurityEvent

Event ID:

4697 — Service Installed in the System

## Detection Logic

Identifies creation of new Windows services including:

- newly registered service names
- service executable file paths
- service start configuration settings
- service installation user context

Service creation activity may indicate:

- attacker persistence establishment
- malware installation behavior
- unauthorized administrative activity
- lateral movement preparation

## Detection Strategy

Attackers frequently create Windows services to maintain persistence across system reboots or to execute malicious payloads with elevated privileges. 
Monitoring service installation activity provides visibility into unauthorized system modification attempts commonly associated with persistence techniques.
Unexpected service creation should be investigated, especially when originating from non-administrative users or unusual execution paths.

## MITRE ATT&CK Mapping

Tactic:

Persistence

Technique:

Create or Modify System Process: Windows Service (T1543.003)

## Analyst Investigation Guidance

Investigate:

- service name legitimacy
- service executable file path location
- user account responsible for service creation
- service start type configuration
- parent process responsible for service installation
- additional suspicious activity on the host
- follow-on execution behavior after service creation

Services created from non-standard directories or unusual user contexts should be treated as high-priority investigation candidates.

## Detection Tuning Recommendations

Detection fidelity can be improved by:

- excluding known enterprise software deployment tools
- excluding approved administrative service installation workflows
- monitoring services created from user-writable directories
- correlating with suspicious parent process execution

Environment-specific tuning helps reduce false positives and improves detection accuracy.

## False Positive Considerations

Legitimate software installations and enterprise configuration management tools commonly create Windows services. 
Analysts should validate whether service creation activity aligns with expected administrative behavior before escalation.
