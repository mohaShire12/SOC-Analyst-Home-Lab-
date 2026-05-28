# 🛡️ SOC Analyst Home Lab Portfolio

Welcome to my comprehensive Security Operations Center (SOC) home lab environment. This repository documents an end-to-end engineering and threat analysis framework, demonstrating hands-on experience in network hardening, host telemetry logging, custom endpoint alerts, and SIEM dashboard engineering.

---

## 🏗️ Lab Environment & Topology
* **SIEM / Analytics Engine:** Splunk Enterprise
* **Firewall / Edge Gateway:** pfSense Firewall Appliance
* **Endpoint Detection & Auditing:** Sysmon (System Monitor) + Windows Event Logs
* **Endpoint Protection & Control:** ManageEngine Endpoint Central Agent
* **Guest Operating Systems:** Kali Linux (Attacker Node), Windows 10 (Target/Victim Network), Windows Server 2019, Windows 10 (Analyst Station)

---

## 📁 Lab Projects Architecture

### 🛑 1. Network Perimeter Scanning & Firewall Policy Validation
* **Location:** `[./01-Firewall-Validation/]`
* **Objective:** Architectural hardening of an internal network split. Simulated an external threat actor utilizing **Kali Linux (Nmap)** executing reconnaissance and vulnerability scans targeting a Windows 10 victim protected by a **pfSense gateway**.
* **Key Achievements:**
  * Successfully transitioned network state from permissive default routing to a heavily restricted, zero-trust profile.
  * Validated policy efficacy by ensuring external port scanning yielded `filtered` or non-responsive behaviors.
  * Audited firewall diagnostics via the **pfSense System Logs**, verifying that incoming malicious connection vectors were actively dropped by the edge `Default Deny` ruleset.
* 📄 **[Read Full Firewall Validation Report](./01-Firewall-Validation/Final%20Firewall%20Lab%20Report.pdf)**

---

### 🦠 2. Malware Delivery, Defense, & SIEM Alert Ingestion
* **Location:** `[./02-Malware-Detection-Pipeline/]`
* **Objective:** Simulating an end-to-end adversarial attack chain—tracking an atomic payload deployment from external infrastructure straight to internal execution and SIEM correlation.
* **Key Achievements:**
  * **Adversarial Setup:** Spun up an ad-hoc payload hosting server on Kali Linux (`192.168.10.40`) on port `8080` using Python's internal HTTP server logic (`python3 -m http.server 8080`).
  * **Endpoint Security Integration:** Leveraged **ManageEngine Endpoint Central** to flag, capture, and track a compiled payload simulation (`shire.exe`) executed on a target Windows 10 asset (`192.168.10.10`).
  * **SIEM Triage:** Built and parsed centralized search parameters inside **Splunk Enterprise** to ingest event streams, map localized execution strings, and successfully validate the status modification of the incident ticket to a confirmed **True Positive**.
* 📄 **[Read Full Detection & Defense Report](./02-Malware-Detection-Pipeline/malwarereport%201.pdf)**

---

### 🔍 3. Endpoint Telemetry Engineering & Advanced Sysmon Queries
* **Location:** `[./03-Sysmon-Telemetry-Analysis/]`
* **Objective:** Building telemetry dashboards inside Splunk to audit, capture, and expose suspicious administrative behaviors on Windows assets via high-fidelity **Sysmon Logs**.
* **Key Achievements:**
  * **Process Profiling:** Authored robust Splunk Search Processing Language (SPL) queries to profile system anomalies by isolating process execution volumes (`EventCode=1 | stats count by Image`).
  * **Heuristic Threat Hunting:** Designed regex-matching SPL criteria to filter and pinpoint obfuscated, malicious, or hidden PowerShell execution methods designed to bypass local policy enforcement:
    ```splunk
    index=* EventCode=1 Image="*powershell.exe*" 
    | eval suspicious=if(match(CommandLine,"-enc|-nop|-w hidden|-exec bypass"), "YES", "NO") 
    | stats count by CommandLine | sort -count
    ```
  * **File Integrity Tracking:** Aggregated Event Code 11 streams to capture real-time execution directories, tracking binary file creations (`TargetFilename="*.exe"`) to surface anomalies immediately.
* 📄 **[Read Full Sysmon Telemetry Report](./03-Sysmon-Telemetry-Analysis/sysmon%20assigment%201.pdf)**

---

## ⚡ Technical Skills Demonstrated
* **Threat Hunting & SIEM:** Advanced SPL Querying, Log Aggregation, Event Correlation (Sysmon Event ID 1 & 11)
* **Network Infrastructure Security:** State-based Packet Filtering, Log Triage, Perimeter Hardening
* **Incident Response Workflows:** Attack Lifecycle Replication, EPP/EDR Alert Verification, True Positive Validation
