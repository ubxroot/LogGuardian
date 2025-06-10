# LogGuardian - Blue Team Security Analyzer

"""
LogGuardian is a command-line tool designed to help blue teams analyze logs and configuration files
for security events and misconfigurations. It aims to provide quick insights into potential threats
and insecure settings, helping to reduce the time to detection and mitigation.
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

# Initialize the Typer application and Console for rich output
app = typer.Typer(help="LogGuardian: Blue Team Security Analyzer")
console = Console()

# --- Configuration for default patterns and remedies ---
DEFAULT_PATTERNS = {
    "ssh_bruteforce": r"(Failed password for|Invalid user|authentication failure).*from\\s+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
    "port_scan": r"Nmap\\s+scan\\s+report\\s+for\\s+([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
    "sql_injection": r"(SELECT\\s+.*FROM|UNION\\s+SELECT|INSERT\\s+INTO|OR\\s+\\d+=\\d+|'or'\\d+='|\\d+'\\s+OR\\s+)",
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
    if CUSTOM_CONFIG_PATH.exists():
        try:
            with open(CUSTOM_CONFIG_PATH, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            console.print(f"[bold red]Error:[/] Could not parse config at {CUSTOM_CONFIG_PATH}.", style="bold red")
            return {}
    return {}

def get_all_patterns_and_remedies():
    custom_config = load_custom_config()
    all_patterns = DEFAULT_PATTERNS.copy()
    all_remedies = DEFAULT_REMEDIES.copy()
    if "patterns" in custom_config:
        all_patterns.update(custom_config["patterns"])
    if "remedies" in custom_config:
        all_remedies.update(custom_config["remedies"])
    return all_patterns, all_remedies

@app.command(name="analyze", help="Analyze a log file for security events.")
def analyze_log(log_file: Path = typer.Argument(..., help="Path to the log file to analyze.")):
    if not log_file.is_file():
        console.print(f"[bold red]Error:[/] Log file not found: {log_file}", style="bold red")
        raise typer.Exit(code=1)

    console.print(f"[bold blue]Analyzing:[/] [cyan]{log_file}[/]\n")
    all_patterns, all_remedies = get_all_patterns_and_remedies()
    detected_events = {}

    try:
        with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                for event_type, pattern in all_patterns.items():
                    if re.search(pattern, line):
                        detected_events.setdefault(event_type, {"count": 0, "lines": []})
                        detected_events[event_type]["count"] += 1
    except IOError as e:
        console.print(f"[bold red]Error:[/] {e}", style="bold red")
        raise typer.Exit(code=1)

    if detected_events:
        console.print("[bold yellow]Suspicious events detected:[/]\n")
        for event_type, data in detected_events.items():
            remedy = all_remedies.get(event_type, "No remedy available.")
            console.print(f"  [green]Event:[/] {event_type}\n  [magenta]Count:[/] {data['count']}\n  [cyan]Remedy:[/] {remedy}\n")
    else:
        console.print("[bold green]No suspicious events found.[/]")

@app.command(name="audit", help="Audit a configuration file for insecure settings.")
def audit_config(
    config_file: Path = typer.Argument(..., help="Path to the config file."),
    audit_type: str = typer.Argument(..., help="Audit type (e.g., ssh)")
):
    if not config_file.is_file():
        console.print(f"[bold red]Error:[/] Config file not found: {config_file}", style="bold red")
        raise typer.Exit(code=1)

    console.print(f"[bold blue]Auditing:[/] [cyan]{config_file}[/]\n")
    all_patterns, all_remedies = get_all_patterns_and_remedies()
    found_issues = {}

    try:
        with open(config_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except IOError as e:
        console.print(f"[bold red]Error:[/] {e}", style="bold red")
        raise typer.Exit(code=1)

    if audit_type.lower() == "ssh":
        console.print("[bold yellow]Checking SSH configuration:[/]\n")
        ssh_patterns = {
            "ssh_insecure_permitrootlogin": r"^\\s*PermitRootLogin\\s+(yes|prohibit-password|without-password)",
            "ssh_passwordauthentication_enabled": r"^\\s*PasswordAuthentication\\s+yes",
        }
        for issue_type, pattern in ssh_patterns.items():
            if re.search(pattern, content, re.MULTILINE | re.IGNORECASE):
                found_issues[issue_type] = {"count": 1}
    else:
        console.print(f"[bold red]Unsupported audit type:[/] {audit_type}", style="bold red")
        raise typer.Exit(code=1)

    if found_issues:
        console.print("[bold yellow]Insecure configurations detected:[/]\n")
        for issue_type in found_issues:
            remedy = all_remedies.get(issue_type, "No remedy available.")
            console.print(f"  [green]Issue:[/] {issue_type}\n  [cyan]Remedy:[/] {remedy}\n")
    else:
        console.print("[bold green]No insecure settings found.[/]")

@app.command(name="update", help="Update LogGuardian via git pull.")
def update_tool():
    repo_path = Path(__file__).resolve().parent
    if not (repo_path / ".git").is_dir():
        console.print("[bold red]Error:[/] Not a git repository.", style="bold red")
        raise typer.Exit(code=1)

    console.print("[bold blue]Updating LogGuardian...[/]")
    try:
        result = subprocess.run(["git", "pull"], cwd=repo_path, capture_output=True, text=True, check=True)
        console.print(f"[bold green]Update successful![/]\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        console.print(f"[bold red]Update failed![/]\n{e.stderr}", style="bold red")
        raise typer.Exit(code=1)
    except FileNotFoundError:
        console.print("[bold red]Git not found. Please install Git.", style="bold red")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
