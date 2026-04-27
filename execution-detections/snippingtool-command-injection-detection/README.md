# Snipping Tool Command Injection Detection

## Purpose

Detects suspicious child process execution spawned by SnippingTool.exe that may indicate command injection activity. Legitimate screenshot activity should not launch command interpreters or scripting engines.

## Telemetry Source

Microsoft Defender Advanced Hunting

Table:
DeviceProcessEvents

## Detection Logic

Identifies command interpreters launched by SnippingTool.exe including:

- cmd.exe
- powershell.exe
- wscript.exe
- cscript.exe
- mshta.exe

Also flags command-line separators commonly associated with chained command execution:

- ;
- &
- |

These separators may indicate command injection or attacker-controlled execution flow.

## Detection Strategy

This behavioral detection identifies anomalous parent-child execution relationships where SnippingTool.exe launches command interpreters. Normal screenshot activity does not require spawning scripting engines or shell interpreters, making this execution chain a strong indicator of potential command injection or exploitation activity.

## MITRE ATT&CK Mapping

Tactic:
Execution

Technique:
Command and Scripting Interpreter (T1059)

## Analyst Investigation Guidance

Investigate:

- parent-child process lineage
- command-line arguments
- execution timing
- originating user context
- process path legitimacy

Unexpected command interpreter execution from SnippingTool.exe is not typical behavior and may indicate exploitation activity.

## False Positive Considerations

Legitimate administrative scripting activity or automation workflows could theoretically invoke command interpreters from SnippingTool.exe, though this behavior is uncommon. Analysts should validate execution context, command-line arguments, and originating user activity before escalation.

