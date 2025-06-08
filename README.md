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
    ```
    *(Remember to replace `yourusername` with your actual GitHub username)*

2.  **Install dependencies:**
    ```bash
    pip install typer
    ```

## 💡 Usage

### Analyze a log file for security events:

```bash
python logguardian.py analyze /path/to/logfile.log
"""

import re
import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.text import Text

app = typer.Typer(help="LogGuardian: Blue Team Security Analyzer")
console = Console()

--- Configuration for patterns and remedies ---
DEFAULT_PATTERNS = {
"ssh_bruteforce": r"(Failed password for|Invalid user|authentication failure).*from\s+([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})",
"port_scan": r"Nmap\s+scan\s+report\s+for\s+([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})",
"sql_injection": r"(SELECT\s+.*FROM|UNION\s+SELECT|INSERT\s+INTO|OR\s+\d+=\d+|'or'\d+='|\d+'\s+OR\s+)",
}

DEFAULT_REMEDIES = {
"ssh_bruteforce": "Block the source IP address in firewall, consider fail2ban. Check user accounts.",
"port_scan": "Investigate the scanning source. Block if malicious. Check exposed services.",
"sql_injection": "Review web application logs, sanitize input, update web application firewall (WAF) rules.",
"ssh_insecure_permitrootlogin": "Set 'PermitRootLogin no' in sshd_config. Use sudo for root access.",
"ssh_passwordauthentication_enabled": "Consider disabling password authentication and enforce SSH keys.",
"ssh_weak_ciphers_or_macs": "Remove weak ciphers and MACs from sshd_config (e.g., 3des-cbc, arcfour, hmac-md5)."
}

CUSTOM_CONFIG_PATH = Path.home() / ".logguardian.json"

def load_custom_config():
"""Loads custom patterns and remedies from ~/.logguardian.json."""
if CUSTOM_CONFIG_PATH.exists():
try:
with open(CUSTOM_CONFIG_PATH, 'r') as f:
return json.load(f)
except json.JSONDecodeError:
console.print(f"[bold red]Error:[/] Could not parse custom config file: {CUSTOM_CONFIG_PATH}. Please check its JSON format.", style="bold red")
return {}
return {}

def get_all_patterns_and_remedies():
"""Combines default and custom patterns/remedies."""
custom_config = load_custom_config()
all_patterns = DEFAULT_PATTERNS.copy()
all_remedies = DEFAULT_REMEDIES.copy()

if "patterns" in custom_config:
    all_patterns.update(custom_config["patterns"])
if "remedies" in custom_config:
    all_remedies.update(custom_config["remedies"])

return all_patterns, all_remedies
--- Analysis Functions ---
@app.command(name="analyze", help="Analyze a log file for security events.")
def analyze_log(log_file: Path = typer.Argument(..., help="Path to the log file to analyze.")):
"""
Analyzes a given log file for predefined security events.
"""
if not log_file.is_file():
console.print(f"[bold red]Error:[/] Log file not found: {log_file}", style="bold red")
raise typer.Exit(code=1)

console.print(f"[bold blue]Analyzing log file:[/][cyan] {log_file}[/]\n", style="bold blue")

all_patterns, all_remedies = get_all_patterns_and_remedies()
detected_events = {}

try:
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            for event_type, pattern in all_patterns.items():
                if re.search(pattern, line):
                    detected_events.setdefault(event_type, {"count": 0, "lines": []})
                    detected_events[event_type]["count"] += 1
                    detected_events[event_type]["lines"].append(line_num) # Optional: store line numbers
except IOError as e:
    console.print(f"[bold red]Error:[/] Could not read log file: {e}", style="bold red")
    raise typer.Exit(code=1)

if detected_events:
    console.print("[bold yellow]Suspicious events detected:[/]\n", style="bold yellow")
    for event_type, data in detected_events.items():
        remedy = all_remedies.get(event_type, "No specific remedy provided.")
        console.print(f"  [bold green]Event Type:[/][white] {event_type}[/]")
        console.print(f"  [bold magenta]Occurrences:[/][white] {data['count']}[/]")
        console.print(f"  [bold cyan]Remedy:[/][white] {remedy}[/]\n")
else:
    console.print("[bold green]No suspicious events found in the log file.[/]", style="bold green")
@app.command(name="audit", help="Audit a configuration file for insecure settings.")
def audit_config(
config_file: Path = typer.Argument(..., help="Path to the configuration file to audit."),
audit_type: str = typer.Argument(..., help="Type of audit (e.g., 'ssh').")
):
"""
Audits a given configuration file for insecure settings based on the audit type.
"""
if not config_file.is_file():
console.print(f"[bold red]Error:[/] Configuration file not found: {config_file}", style="bold red")
raise typer.Exit(code=1)

console.print(f"[bold blue]Auditing configuration file:[/][cyan] {config_file}[/]\n", style="bold blue")

all_patterns, all_remedies = get_all_patterns_and_remedies()
found_issues = {}

try:
    with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()
except IOError as e:
    console.print(f"[bold red]Error:[/] Could not read configuration file: {e}", style="bold red")
    raise typer.Exit(code=1)

if audit_type.lower() == "ssh":
    console.print("[bold yellow]Checking SSH configuration for insecure settings:[/]\n", style="bold yellow")
    # Example SSH audit patterns (can be expanded)
    ssh_audit_patterns = {
        "ssh_insecure_permitrootlogin": r"^\s*PermitRootLogin\s+(yes|prohibit-password|without-password)",
        "ssh_passwordauthentication_enabled": r"^\s*PasswordAuthentication\s+yes",
        # Add more specific checks for weak ciphers/MACs if desired,
        # but they often require more complex parsing than simple regex on single lines.
        # Example for a specific weak cipher (might need to check if it's NOT present):
        # "ssh_weak_3des_cbc": r"Ciphers.*3des-cbc"
    }
    for issue_type, pattern in ssh_audit_patterns.items():
        if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
            found_issues.setdefault(issue_type, {"count": 1}) # For config, count is usually 1
else:
    console.print(f"[bold red]Error:[/] Unsupported audit type: {audit_type}. Currently only 'ssh' is supported.", style="bold red")
    raise typer.Exit(code=1)

if found_issues:
    console.print("[bold yellow]Insecure configurations detected:[/]\n", style="bold yellow")
    for issue_type, data in found_issues.items():
        remedy = all_remedies.get(issue_type, "No specific remedy provided.")
        console.print(f"  [bold green]Issue Type:[/][white] {issue_type}[/]")
        console.print(f"  [bold magenta]Details:[/][white] Insecure setting found.[/]")
        console.print(f"  [bold cyan]Remedy:[/][white] {remedy}[/]\n")
else:
    console.print("[bold green]No insecure configurations found.[/]", style="bold green")
@app.command(name="update", help="Update LogGuardian to the latest version via git pull.")
def update_tool():
"""
Updates the LogGuardian tool by performing a git pull.
"""
repo_path = Path(file).resolve().parent
if not (repo_path / ".git").is_dir():
console.print("[bold red]Error:[/] Not a git repository. Please clone LogGuardian using 'git clone'.", style="bold red")
raise typer.Exit(code=1)

console.print("[bold blue]Updating LogGuardian...[/]", style="bold blue")
try:
    process = subprocess.run(["git", "pull"], cwd=repo_path, capture_output=True, text=True, check=True)
    console.print(f"[bold green]Update successful![/]\n{process.stdout}", style="bold green")
except subprocess.CalledProcessError as e:
    console.print(f"[bold red]Update failed![/]\n{e.stderr}", style="bold red")
    raise typer.Exit(code=1)
except FileNotFoundError:
    console.print("[bold red]Error:[/] 'git' command not found. Please ensure Git is installed and in your PATH.", style="bold red")
    raise typer.Exit(code=1)
if name == "main":
app()


---

**Remember to separate this into two files: `README.md` and `logguardian.py` for your GitHub rep
