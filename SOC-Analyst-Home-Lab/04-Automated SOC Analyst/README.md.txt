# Automated SOC Analyst: AI-Driven SIEM Alert Enrichment & Playbook Orchestration

## 📌 Project Overview
This project demonstrates a production-grade Tier 3 SOC Automation / SOAR engineering pipeline. It automates the extraction of security telemetry from an enterprise SIEM (Splunk), routes the payload through an orchestration layer (n8n), and uses an Advanced Language Model (Llama 3.3 via Groq) acting as an automated SOC Analyst to triage, contextualize, and analyze system alerts in real-time.

### Architectural Blueprint
* **Edge Routing & Segmentation:** pfSense Firewall managing multi-zone enclaves (WAN, SOC, USERS, SERVERS).
* **Telemetry & Detection:** Windows 10 Endpoint monitored via security data streams indexed directly inside Splunk Enterprise.
* **SOAR Orchestration:** n8n workflow engine managing automated data pipelines.
* **Cognitive Analysis Engine:** Groq API hosting `llama-3.3-70b-versatile` utilizing context-aware prompt templates for log analysis.

---

## 🛠️ Infrastructure & Network Architecture
The laboratory network is segmented through a virtualized **pfSense** security gateway to reflect an enterprise perimeter layout:

* **Attacker Enclave (WAN):** `10.128.120.200` (Kali Linux simulation zone)
* **Internal Target Enclave (USERS):** `192.168.20.10` (Windows 10 target endpoint)
* **Security Operations Enclave (SOC):** `192.168.10.10` (Splunk Enterprise Indexer & n8n orchestration node)