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
cd logguardian  # Your project directory

# Initialize Git
git init

# Create README
echo "# LogGuardian" > README.md

# Create Python .gitignore
curl -o .gitignore https://raw.githubusercontent.com/github/gitignore/main/Python.gitignore

# Add MIT License
curl -o LICENSE https://raw.githubusercontent.com/github/choosealicense.com/gh-pages/_licenses/mit.txt
# Clone the repo
git clone https://github.com/ubxroot/LogGuardian.git
cd LogGuardian

# Install dependencies
pip install -r requirements.txt

# Run it
python logguardian.py analyze /path/to/logfile.log --output-format table
python logguardian.py config-check /path/to/config/file.conf ssh
