========================================================================
 POWERSHELL MALWARE DETECTION & THREAT HUNTING
========================================================================

Overview
--------
This repository provides a deployment and testing blueprint for simulating, 
logging, and automating responses to obfuscated PowerShell attacks and anomalous 
parent-child process patterns. It leverages Sysmon, Windows ScriptBlock auditing, 
Splunk/Wazuh SIEM engines, and n8n SOAR automated triage loops.

Target Environment Context (Lab Artifacts)
-------------------------------------------
- Analyzed Host: The-Analyst
- Core Logs Used: Sysmon (Event ID 1), Microsoft-Windows-PowerShell (Event ID 4104)
- Attack Focus: Obfuscation evasion (-enc), Profile Bypass (-nop), Window Hiding (-w hidden)

Repository Structure
--------------------
├── powershell_threat_hunting_automation_report.pdf  <- Full Technical Analysis Report
└── README.txt                                       <- Project Overview and Instructions

Adversary Simulation Test Cases
-------------------------------
Execute the following inside an isolated testing environment to generate telemetry:

1. Execution Policy Bypass:
   powershell.exe -ExecutionPolicy Bypass -NoProfile -Command "Write-Host 'Execution Policy Bypassed'"

2. Hidden Payload Network Stager (EICAR Test File):
   powershell.exe -WindowStyle Hidden -NoProfile -Command "Invoke-WebRequest -Uri 'https://secure.eicar.org/eicar.com' -OutFile '$env:TEMP\eicar.com'"

3. Base64 Command Encoding (T1027):
   powershell.exe -ExecutionPolicy Bypass -EncodedCommand uwb0ageacgb0acoauabyag8aywb1ahmacwagagmayqbsagmalgb1ahgazqa=

4. Anomalous Parent Generation:
   Execute shell instructions via application runtimes like Node.exe, MSHTA, or WScript.

SIEM Detection Signatures (Splunk SPL)
--------------------------------------
* Evasion Switches Detection:
  index=* "sysmon" EventCode=1
  | eval CommandLine=lower(CommandLine)
  | search CommandLine="*-enc*" OR CommandLine="*-encodedcommand*" OR CommandLine="*-nop*" OR CommandLine="*-noprofile*" OR CommandLine="*hidden*"
  | table _time, Computer, User, ParentImage, Image, CommandLine

* Non-Standard Process Parents Hunt:
  index=* "sysmon" EventCode=1
  | eval ParentImage=lower(ParentImage), Image=lower(Image)
  | search Image="*powershell.exe" AND (ParentImage="*node.exe" OR ParentImage="*cmd.exe" OR ParentImage="*mshta.exe" OR ParentImage="*wscript.exe")
  | table _time, Computer, ParentImage, Image, CommandLine

Automation Pipeline Logic (SOAR with n8n + VirusTotal)
------------------------------------------------------
1. Ingestion: HTTP Webhook listener nodes receive automated JSON payloads from SIEM whenever queries alert.
2. Extraction: Regular expression nodes comb command data arrays to extract domain targets or binary file hashes.
3. Enrichment: An API calling block invokes the VirusTotal enrichment endpoint using saved secrets.
4. Logic Routing: Conditional logic routes high-risk results (threat matches > 0) to priority engineering channels.

Hardening Directives
---------------------
- Enforce PowerShell Constrained Language Mode (CLM) across normal user environments.
- Roll out Windows Defender Application Control (WDAC) or AppLocker restrictions.
- Globally enforce Event ID 4104 (ScriptBlock Logging) via GPO to nullify Base64 obfuscation.
========================================================================