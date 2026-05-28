================================================================================
ACTIVE DIRECTORY BRUTE FORCE DETECTION & INVESTIGATION REPORT
================================================================================
Repository/Project Name: AD-BruteForce-Detection-SIEM
Category: Blue Teaming / Detection Engineering / Security Analytics
Target Platform: Windows Server 2019 / Active Directory Domain
Monitoring Stack: Splunk Enterprise SIEM / Event Logs

--------------------------------------------------------------------------------
1. PROJECT OVERVIEW
--------------------------------------------------------------------------------
This project documents the simulation, detection engineering, and data analysis 
of an automated brute force attack targeting Active Directory domain credentials via 
Remote Desktop Protocol (RDP). The objective was to configure a secure lab environment, 
execute high-velocity dictionary password guessing, and engineer advanced SIEM logic 
to isolate, track, and profile the adversary session metrics.

--------------------------------------------------------------------------------
2. ENVIRONMENT ARCHITECTURE
--------------------------------------------------------------------------------
* Domain Controller: Windows Server 2019 (Host: The-Server.Lab.Local / 192.168.30.10)
* SIEM Infrastructure: Splunk Enterprise instance for central log parsing
* Logging Agents: Windows Security Log Subsystem via WinEventLog channels
* Gateway/Firewall: Segmented virtual network using strict zone policies

--------------------------------------------------------------------------------
3. ATTACK SIMULATION PROFILE
--------------------------------------------------------------------------------
* Attack Vector: Automated Password Guessing (RDP protocol level)
* Adversary Weaponry: Hydra v9.6 Network Login Cracker
* Attacker IP: 192.168.30.10
* Primary Targeted User: domain_admin_account
* Execution String:
  hydra -l domain_admin_account -P passwordlist.txt 192.168.30.10 rdp -V

--------------------------------------------------------------------------------
4. DETECTION LOGIC & SIEM CORRELATION
--------------------------------------------------------------------------------
The primary telemetry source relied upon is Windows Security Event ID 4625 
(An account failed to log on) with a specific filter for Logon Type 3 (Network logon).

To convert raw repetitive failure events into a single actionable incident card, 
the following advanced Splunk Search Processing Language (SPL) query was engineered:

-------------------- SPLUNK ADVANCED DETECTION QUERY ---------------------------
index=* host="The-Server" EventCode=4625
| stats
    earliest(_time) as first_attempt
    latest(_time) as last_attempt
    dc(Account_Name) as unique_accounts_targeted
    values(Account_Name) as targeted_users
    values(Failure_Reason) as failure_reasons
    values(Logon_Type) as logon_methods
    count by Source_Network_Address
| eval duration_seconds = last_attempt - first_attempt
| eval attempts_per_second = round(count / max(duration_seconds, 1), 2)
| where count > 5
| convert ctime(first_attempt) ctime(last_attempt)
| rename Source_Network_Address as "Attacker IP", unique_accounts_targeted as "Total Accounts Hit", targeted_users as "Targeted Accounts", failure_reasons as "Windows Error Message", logon_methods as "Logon Type ID", attempts_per_second as "Attack Speed (eps)"
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
5. FORENSIC FINDINGS SUMMARY
--------------------------------------------------------------------------------
Based on the advanced aggregation logic, the following session data was parsed:
* Attacker Source IP: 192.168.30.10
* Capture Window: 17:32:47.593 to 17:32:51.738 (Duration: 4.145 seconds)
* Total Correlated Events: 10 failed login attempts
* Calculated Velocity: 2.41 Events Per Second (eps)
* Target Users Flagged: domain_admin_account
* Active Directory Reason: Unknown user name or bad password

--------------------------------------------------------------------------------
6. MITRE ATT&CK FRAMEWORK MAPPING
--------------------------------------------------------------------------------
* Tactic: Credential Access
  - Technique: T1110.001 (Brute Force: Password Guessing)
* Tactic: Defense Evasion
  - Technique: T1078.002 (Valid Accounts: Domain Accounts)

--------------------------------------------------------------------------------
7. ACTIONABLE HARDENING STRATEGIES
--------------------------------------------------------------------------------
1. Implement Domain Account Lockout Policies via administrative GPO templates.
2. Limit RDP network visibility by requiring Network Level Authentication (NLA) 
   and forcing traffic through an isolated secure administrative jump box or VPN gateway.
3. Configure conditional access policies to require MFA for all administrative 
   network logon types.
4. Establish real-time alerting inside the SIEM ecosystem leveraging the 
   velocity thresholds established in this investigation report.

--------------------------------------------------------------------------------
8. HOW TO USE THIS REPOSITORY
--------------------------------------------------------------------------------
* /docs: Houses the polished executive PDF forensic report artifact.
* /queries: Stores reusable Splunk SPL and alert threshold configurations.
* /simulation: Contains sample sanitized dictionary formats for validation tests.
================================================================================
