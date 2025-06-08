# LogGuardian 🔐

**LogGuardian** is a Blue Team log and config analyzer designed to help detect brute force attacks, misconfigurations, and other security events in real-time.

## Features
- Detects SSH brute-force attempts and port scans
- Checks configuration files (e.g., SSH) for insecure settings
- Color-coded terminal output or JSON format
- CLI-first, lightweight, and extensible

## Installation

```bash
git clone https://github.com/yourusername/logguardian.git
cd logguardian
pip install -r requirements.txt
cd logguardian

## Clone repository

git clone https://github.com/yourusername/logguardian.git
cd logguardian

## Install dependencies
pip install -r requirements.txt

## Make script executable
chmod +x logguardian.py

## Install system dependency for file type detection
sudo apt-get install libmagic1  # For Debian/Ubuntu
## Log analysis with table output
./logguardian.py analyze /var/log/auth.log

## Binary analysis with CVE checks and HTML report
./logguardian.py scan-binary suspicious.exe --cve --output-format html --output-file report.html

## SSH config security audit
./logguardian.py config-check /etc/ssh/sshd_config ssh
