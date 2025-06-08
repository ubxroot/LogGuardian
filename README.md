#!/usr/bin/env python3
"""
LogGuardian - Blue Team Security Analyzer
Simple CLI tool for log analysis and security checks
"""

import typer
import re
import sys
import json
import subprocess
from pathlib import Path
from typing import List, Dict
from collections import defaultdict

app = typer.Typer()

# ======================
# Core Configuration
# ======================
CONFIG_FILE = Path.home() / ".logguardian.json"
DEFAULT_PATTERNS = {
    "ssh_bruteforce": r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
    "port_scan": r"Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+",
    "sql_injection": r"(\'|--|;|UNION.*SELECT)",
}
DEFAULT_REMEDIES = {
    "ssh_bruteforce": "Block IP and enable fail2ban",
    "port_scan": "Investigate source IP",
    "sql_injection": "Check web application firewall",
}

# ======================
# Helper Functions
# ======================
def show_banner():
    print(r"""
    ╦  ╦┌─┐┌─┐┬┌─┌─┐┬─┐
    ╚╗╔╝│ ││ │├┴┐├┤ ├┬┘
     ╚╝ └─┘└─┘┴ ┴└─┘┴└─
    Security Log Analyzer v1.0
    """)

def load_config() -> Dict:
    config = {"patterns": DEFAULT_PATTERNS, "remedies": DEFAULT_REMEDIES}
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config.update(json.load(f))
    return config

def save_config(config: Dict):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)

# ======================
# Analysis Functions
# ======================
def analyze_logs(file_path: Path) -> Dict[str, int]:
    config = load_config()
    results = defaultdict(int)
    
    try:
        with open(file_path) as f:
            for line in f:
                for name, pattern in config["patterns"].items():
                    if re.search(pattern, line, re.IGNORECASE):
                        results[name] += 1
    except FileNotFoundError:
        print(f"Error: File {file_path} not found")
        sys.exit(1)
        
    return results

def audit_config(config_path: Path, config_type: str) -> List[str]:
    issues = []
    try:
        with open(config_path) as f:
            content = f.read().lower()
            
            if config_type == "ssh":
                if "permitrootlogin yes" in content:
                    issues.append("Insecure: Root login enabled")
                if "passwordauthentication yes" in content:
                    issues.append("Insecure: Password authentication enabled")
                    
    except Exception as e:
        print(f"Config error: {str(e)}")
        sys.exit(1)
        
    return issues

# ======================
# CLI Commands
# ======================
@app.command()
def analyze(file_path: str):
    """Analyze log file for security events"""
    show_banner()
    results = analyze_logs(Path(file_path))
    
    print("\nSecurity Findings:")
    for event, count in results.items():
        print(f"• {event}: {count} occurrences")
        
    if not results:
        print("No security events found")

@app.command()
def audit(config_path: str, config_type: str):
    """Check configuration file for security issues"""
    show_banner()
    issues = audit_config(Path(config_path), config_type)
    
    if issues:
        print(f"Found {len(issues)} issues in {config_path}:")
        for issue in issues:
            print(f"• {issue}")
    else:
        print("No security issues found")

@app.command()
def update():
    """Update LogGuardian to latest version"""
    show_banner()
    try:
        result = subprocess.run(["git", "pull"], capture_output=True, text=True)
        print(result.stdout)
        if result.returncode == 0:
            print("Update successful")
        else:
            print("Update failed")
    except Exception as e:
        print(f"Update error: {str(e)}")

if __name__ == "__main__":
    app()
