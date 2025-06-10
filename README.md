# LogGuardian - Blue Team Security Analyzer

![LogGuardian Logo/Banner (Optional - you can add an image here)](https://img.shields.io/badge/Blue%20Team-Security-blue?style=for-the-badge&logo=shield)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

LogGuardian is a command-line tool designed to help blue teams analyze logs and configuration files for security events and misconfigurations. It aims to provide quick insights into potential threats and insecure settings, helping to reduce the time to detection and mitigation.

## ✨ Features

## 🔍 Binary File Scanning 

* Analyze .exe, .dll, .bin, .elf, and other formats.
* Extract headers, strings, hashes (MD5, SHA1, SHA256).
* Enrich results with VirusTotal (optional), YARA, and known malware signatures.

## 📁 Log Analysis Engine

* Supports log formats: syslog, auth.log, Windows Event Logs (EVTX), Apache/Nginx access logs, and custom JSON.
* Regex and rule-based parsing.
* Custom rules for detecting brute force, privilege escalation, and suspicious behavior.

## 🚨 Threat Intelligence Correlation

* Integrates with threat feeds like AbuseIPDB, AlienVault OTX, and custom TI sources.
* Auto-correlates IPs, hashes, domains found in logs/binaries.
* IOC hunting with local cache for offline use.

## 🛡️ Real-time Monitoring
* Real-time tailing and monitoring of logs.
* Alerts with color-coded output in CLI.
* Optional webhook/Slack notification integration.

## 🔐 File Integrity and IOC Scanner
* Recursively monitors directories for file changes.
* Detects added/modified binaries with signature mismatches.
* Supports custom scan policies for file integrity checks.

## 📊 Output and Reporting
* Supports output formats: table, json, csv, html.
* Generates summary reports for each analysis session.
* Option to export reports to PDF (via CLI flag).

## **🚀 Installation**

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/ubxroot/LogGuardian.git]
    cd logguardian
    pip install -r requirements.txt
    ```

2.  **Install dependencies:**
    ```bash
    pip install typer
    pip install -r requirements.txt
    ```

## 💡 Usage

# Basic log analysis
**python logguardian.py analyze /var/log/auth.log --output-format table**

# Binary file scan
**python logguardian.py scan /samples/malware.exe --verbose**

# Enable threat intelligence lookup
**python logguardian.py analyze /logs/web.log --enable-ti**

# Live directory monitoring
**python logguardian.py monitor /var/log --rules rules.json**

## 📁 Directory Structure

* logguardian/
* 🗂 core/              # Main engine modules
* 🗂 rules/             # Predefined and custom rule sets
* 🗂 reports/           # Output report files
* 🗂 examples/          # Sample logs and binaries
* 🗂 utils/             # Helper functions
* 🔍 logguardian.py     # Entry point CLI
* 🔍 README.md

## 🌐 Integrations

**Platform**

 **Supported**

* **Linux       ✅**
* **Windows     ✅**
* **MacOS       ✅**

## 📚 Documentation

* **📘 Full Wiki Documentation**
* **📖 CLI Reference**
* **🧪 Testing Scenarios**

## 🛡️ License

* **LogGuardian is licensed under the MIT License. See the LICENSE file for more details.**
