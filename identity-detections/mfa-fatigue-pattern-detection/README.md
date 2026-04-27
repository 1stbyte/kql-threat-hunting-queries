# MFA Fatigue Pattern Detection

Behavioral detection identifying repeated authentication failures followed by a successful logon that may indicate MFA fatigue or password spraying activity.

## Purpose

Detects suspicious authentication patterns where multiple failed logon attempts occur before a successful sign-in event. This behavior may indicate attackers attempting credential guessing or repeated push-notification approval attempts designed to exhaust users into accepting malicious login requests.

## Telemetry Source

Microsoft Sentinel / Windows Security Logs / Microsoft Entra ID

Tables:

SecurityEvent  
SigninLogs (optional enhancement)  
AuditLogs (optional enrichment)

## Detection Logic

Identifies authentication activity containing:

- multiple failed logon attempts (Event ID 4625)
- followed by a successful logon event (Event ID 4624)
- originating from the same account
- within a short observation window

This pattern may indicate:

- password spraying
- credential guessing attempts
- MFA fatigue attacks
- attacker persistence during authentication attempts

## Detection Strategy

Attackers commonly generate repeated authentication attempts against a user account hoping the target eventually approves a login request or that a valid credential pair is identified through trial attempts. Monitoring sequences of failed authentication attempts followed by a successful sign-in provides early visibility into potential identity compromise activity.

Correlating authentication telemetry with Microsoft Entra ID SigninLogs improves detection confidence by identifying:

- repeated MFA push prompts
- risky sign-in activity
- unfamiliar device sign-ins
- unfamiliar location sign-ins

## MITRE ATT&CK Mapping

Tactic:

Credential Access

Technique:

Brute Force (T1110)

Related Technique:

Valid Accounts (T1078)

## Analyst Investigation Guidance

Investigate:

- originating IP address
- authentication timing patterns
- geographic login anomalies
- unfamiliar devices
- sign-in risk indicators (if available)
- additional authentication attempts from the same account
- follow-on activity after successful login

Authentication success immediately following multiple failures should be reviewed carefully to determine whether access resulted from legitimate user behavior or attacker persistence.

## Detection Tuning Recommendations

Detection fidelity can be improved by:

- adjusting failed-attempt thresholds (example: 5–10 attempts)
- restricting correlation windows (example: 10–30 minutes)
- excluding trusted corporate VPN address ranges
- excluding known service accounts
- correlating with Entra ID RiskLevelDuringSignIn

Environment-specific tuning significantly reduces false positives.

## False Positive Considerations

Users occasionally mistype passwords before successfully authenticating. Analysts should validate whether login attempts originated from:

- trusted locations
- known devices
- corporate VPN infrastructure
- expected user activity patterns

before escalation.
