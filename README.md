# KQL Threat Hunting Queries

This repository contains Microsoft Defender Advanced Hunting KQL (Kusto) queries developed for behavioral endpoint threat detection, identity investigations, and SOC threat hunting workflows.

These detections focus on identifying attacker tradecraft including defense evasion, suspicious process execution, identity misuse, and Living-off-the-Land binary (LOLBins) abuse.

## Detection Categories

### Endpoint Detections
Behavioral queries targeting suspicious process execution patterns such as:

- EDR tampering attempts
- Encoded PowerShell activity
- Command-line abuse indicators
- Suspicious parent-child process relationships

### Identity Detections

Queries designed to detect abnormal identity activity including:

- Suspicious device registration ownership changes
- MFA fatigue patterns
- Azure AD / Entra ID anomalies

### Execution & Persistence Monitoring

Detection logic aligned to MITRE ATT&CK techniques such as:

- Execution via scripting interpreters
- Persistence through service creation
- Defense evasion via security control tampering

## Data Sources

Queries leverage Microsoft Defender Advanced Hunting telemetry including:

- DeviceProcessEvents
- AuditLogs
- SecurityEvent

## Purpose

These queries demonstrate how endpoint telemetry can be transformed into actionable detection logic supporting SOC investigations and detection engineering workflows.
