# LogGuardian - Blue Team Security Analyzer

![LogGuardian Logo/Banner (Optional - you can add an image here)](https://img.shields.io/badge/Blue%20Team-Security-blue?style=for-the-badge&logo=shield)
![Python Version](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

LogGuardian is a command-line tool designed to help blue teams analyze logs and configuration files for security events and misconfigurations. It aims to provide quick insights into potential threats and insecure settings, helping to reduce the time to detection and mitigation.

## ✨ Features

* **Detects SSH brute-force attempts:** Identifies multiple failed SSH login attempts.
* **Detects port scanning activity:** Flags suspicious network scanning patterns.
* **Detects SQL injection attempts in logs:** Scans web server or application logs for common SQLi signatures.
* **Audits SSH configuration files for insecure settings:** Checks for weak ciphers, insecure authentication methods, and other common misconfigurations.
* **Simple, color-coded terminal output:** Easy-to-read results for quick analysis.
* **Supports custom detection patterns via a config file:** Extend detection capabilities to suit your specific needs.
* **Self-update via `git pull`:** Keep your tool up-to-date with the latest features and patterns.
* **Minimal dependencies and easy to use:** Get up and running quickly.

## 🚀 Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/yourusername/logguardian.git](https://github.com/yourusername/logguardian.git)
    cd logguardian
    pip install -r requirements.txt
    ```
    *(Remember to replace `yourusername` with your actual GitHub username)*

2.  **Install dependencies:**
    ```bash
    pip install typer
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

Platform

Supported

Linux

✅

Windows

✅

MacOS

✅

## 📚 Documentation

📘 Full Wiki Documentation

📖 CLI Reference

🧪 Testing Scenarios

## 🛡️ License

LogGuardian is licensed under the MIT License. See the LICENSE file for more details.
