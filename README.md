#!/usr/bin/env python3
"""
LogGuardian - Blue Team Security Analyzer 🔐
Unified CLI tool for log analysis, config auditing, and security monitoring.
"""

import typer
import re
import json
import sys
import subprocess
import hashlib
import requests
import os
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Optional
from rich.console import Console
from rich.table import Table
import pyfiglet

app = typer.Typer()
console = Console()

# ====== Banner ======
def show_banner():
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]LogGuardian - Blue Team Security Analyzer v1.0[/bright_yellow]\n")

# ====== Default Patterns and Remedies ======
DEFAULT_PATTERNS = {
    "ssh_bruteforce": r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
    "port_scan": r"Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+",
    "sql_injection": r"(\'|--|;|UNION.*SELECT)",
    "xss_attempt": r"<script.*?>.*?</script>",
    "cve": r"CVE-\d{4}-\d{4,7}",
}
DEFAULT_REMEDIES = {
    "ssh_bruteforce": "Block source IP, enable fail2ban, and use key-based authentication.",
    "port_scan": "Investigate source IP, consider blocking, and monitor for further activity.",
    "sql_injection": "Sanitize inputs, use parameterized queries, and check WAF logs.",
    "xss_attempt": "Sanitize user input, set CSP headers, and review web app code.",
    "cve": "Check system for relevant patches and update vulnerable software."
}

CONFIG_FILE = Path.home() / ".logguardian_config.json"

def load_patterns():
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            data = json.load(f)
        patterns = {**DEFAULT_PATTERNS, **data.get("patterns", {})}
        remedies = {**DEFAULT_REMEDIES, **data.get("remedies", {})}
    else:
        patterns = DEFAULT_PATTERNS.copy()
        remedies = DEFAULT_REMEDIES.copy()
    # Compile regex
    patterns = {k: re.compile(v, re.IGNORECASE) for k, v in patterns.items()}
    return patterns, remedies

def save_patterns(patterns, remedies):
    # Save only custom (non-default) patterns/remedies
    custom_patterns = {k: v.pattern for k, v in patterns.items() if k not in DEFAULT_PATTERNS}
    custom_remedies = {k: v for k, v in remedies.items() if k not in DEFAULT_REMEDIES}
    with open(CONFIG_FILE, "w") as f:
        json.dump({"patterns": custom_patterns, "remedies": custom_remedies}, f, indent=2)

# ====== Log Analysis ======
def analyze_log_file(log_file: Path, patterns, remedies):
    stats = defaultdict(int)
    findings = defaultdict(list)
    total_lines = 0

    with open(log_file, encoding="utf-8", errors="ignore") as f:
        for line in f:
            total_lines += 1
            for name, pattern in patterns.items():
                if pattern.search(line):
                    stats[name] += 1
                    findings[name].append(line.strip())
    return stats, findings, total_lines

# ====== Config Analysis ======
def analyze_config_file(config_file: Path, config_type: str):
    issues = []
    with open(config_file, encoding="utf-8", errors="ignore") as f:
        content = f.read()
        if config_type == "ssh":
            if "PermitRootLogin yes" in content:
                issues.append("PermitRootLogin is enabled (should be 'no').")
            if "PasswordAuthentication yes" in content:
                issues.append("PasswordAuthentication is enabled (should be 'no').")
        # Extend for nginx/apache as needed
    return issues

# ====== Threat Intel (Dummy/Optional) ======
def check_threat_ip(ip: str) -> bool:
    # Example: Replace with actual API if needed
    # resp = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}", headers=...)
    # return resp.json().get("data", {}).get("abuseConfidenceScore", 0) > 50
    return False

# ====== CLI Commands ======
@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Path to log file"),
    output: Optional[str] = typer.Option("table", help="Output format: table/json"),
):
    """Analyze log files for security events."""
    show_banner()
    patterns, remedies = load_patterns()
    stats, findings, total_lines = analyze_log_file(log_path, patterns, remedies)

    if output == "json":
        result = {
            "file": str(log_path),
            "total_lines": total_lines,
            "stats": dict(stats),
            "findings": findings,
        }
        console.print_json(json.dumps(result, indent=2))
    else:
        table = Table(title=f"Log Analysis: {log_path.name}", show_header=True, header_style="bold blue")
        table.add_column("Event", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Remedy", style="green")
        for k, v in stats.items():
            table.add_row(k, str(v), remedies.get(k, ""))
        console.print(table)
        if not stats:
            console.print("[green]No suspicious events detected.[/green]")
        else:
            for k, lines in findings.items():
                console.print(f"[yellow]{k} findings:[/yellow]")
                for l in lines[:5]:
                    console.print(f"  [white]{l}[/white]")
                if len(lines) > 5:
                    console.print(f"  ...and {len(lines)-5} more\n")

@app.command()
def config_check(
    config_path: Path = typer.Argument(..., help="Path to config file"),
    config_type: str = typer.Argument(..., help="Config type (ssh/nginx/apache)"),
):
    """Audit configuration files for insecure settings."""
    show_banner()
    issues = analyze_config_file(config_path, config_type)
    if issues:
        console.print(f"[red]Insecure settings detected in {config_path}:[/red]")
        for i in issues:
            console.print(f"  [yellow]- {i}[/yellow]")
    else:
        console.print(f"[green]No critical issues found in {config_path}.[/green]")

@app.command()
def patterns():
    """Show current detection patterns."""
    show_banner()
    patterns, remedies = load_patterns()
    table = Table(title="Detection Patterns", show_header=True, header_style="bold blue")
    table.add_column("Name", style="cyan")
    table.add_column("Regex", style="magenta")
    table.add_column("Remedy", style="green")
    for k, v in patterns.items():
        table.add_row(k, v.pattern, remedies.get(k, ""))
    console.print(table)

@app.command()
def add_pattern(
    name: str = typer.Argument(..., help="Pattern name"),
    regex: str = typer.Argument(..., help="Regex pattern"),
    remedy: str = typer.Argument(..., help="Remedy/response"),
):
    """Add a custom detection pattern."""
    patterns, remedies = load_patterns()
    try:
        patterns[name] = re.compile(regex, re.IGNORECASE)
        remedies[name] = remedy
        save_patterns(patterns, remedies)
        console.print(f"[green]Pattern '{name}' added.[/green]")
    except re.error as e:
        console.print(f"[red]Invalid regex: {e}[/red]")

@app.command()
def update():
    """Update LogGuardian via git pull."""
    show_banner()
    try:
        result = subprocess.run(['git', 'pull'], capture_output=True, text=True, check=True)
        console.print(result.stdout)
        console.print("[green]Update completed successfully.[/green]")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Update failed: {e.stderr}[/red]")

@app.command()
def version():
    """Show version info."""
    show_banner()
    console.print("[bold]LogGuardian version 1.0[/bold]")

@app.command()
def help():
    """Show help."""
    show_banner()
    console.print("""
[bold]Usage:[/bold]
  logguardian analyze <logfile> [--output table|json]
  logguardian config-check <configfile> <ssh|nginx|apache>
  logguardian patterns
  logguardian add-pattern <name> <regex> <remedy>
  logguardian update
  logguardian version
""")

if __name__ == "__main__":
    app()
