# Name: Salman Ahmed
# Student ID: k2554693
# Module Code CI7526
# Module Title Cyber and Artificial Intelligence (Applications)
# Assessment Title Agentic AI for Cyber Security
# Kingston University London


# SentryNode v1.0 | IoT Security Forensics & Risk Orchestration

**A Synthetic Forensics Platform for Residential IoT Exposure Analysis**

---

## 🚀 Project Overview
SentryNode is a high-fidelity security simulation environment designed to bridge the gap between technical network telemetry and physical home safety. Developed as a response to the evolving 2026 IoT threat landscape, the platform models sophisticated attack vectors—specifically the **Aisuru Botnet** and **CVE-2025-4008** exploits—and translates them into actionable "First Aid" intelligence for homeowners.

## 🛠️ Key Architectural Features
* **Dynamic Scenario Engine:** Supports four distinct operational states (Safe, Probing, Attack, Breach) to demonstrate the full incident response lifecycle.
* **NIST IR 8425 Compliance Auditor:** A built-in automated auditor that evaluates generated telemetry against international standards for Identity, Traceability (MAC-level), and Signaling.
* **Forensic Realism:** Implements "Clustered Timing" for volumetric attacks and "Spaced Reconnaissance" for port-probing sequences, mimicking actual adversary behavior.
* **Risk Persistence Logic:** Automatically escalates threat levels based on multi-vector targeting on single assets.
* **Modern SaaS Dashboard:** A professional dark-mode UI built with Flask and Tailwind CSS, prioritizing user experience (UX) and clarity of risk.

---

## 📊 Technical Stack
| Component | Technology |
| :--- | :--- |
| **Backend** | Python 3.12, Flask |
| **Frontend** | HTML5, Tailwind CSS, Jinja2 |
| **Standardization** | NIST IR 8425 Core Baseline |
| **Deployment** | GitHub Codespaces / Local Virtual Environments |

---

## ⚙️ Installation & Usage

### 1. Environment Setup
Ensure you have Python 3.x installed and the required dependencies:
```bash
pip install flask
2. Launching the SaaS Dashboard (Web)
Bash
python app.py
Access the UI via http://localhost:8000 or the forwarded port in your cloud environment.

3. Running the Terminal Controller (CLI)
Bash
python main.py [SCENARIO_NAME]
# Options: SAFE, PROBING, ATTACK, BREACH
📂 Project Structure
app.py: The master web orchestration layer.

engine.py: The core simulation and risk-scoring logic.

auditor.py: The NIST compliance verification module.

assets.py: The immutable device profile library.

formatter.py: Data transformation for JSON/CSV exports.

templates/: UI/UX dashboard components.

🛡️ Compliance & Standards
SentryNode is built to satisfy the NIST IR 8425 (Consumer IoT Cybersecurity) guidelines. Every event log is audited for:

Asset Identification: Unique device_id per event.

Hardware Traceability: Locally administered mac_address logging.

Severity Signaling: Precise mapping of event types to priority levels.
