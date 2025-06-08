#!/usr/bin/env python3
"""
LogGuardian - Blue Team Security Analyzer 🔐
Robust CLI tool for security log analysis and configuration auditing
"""

import typer
import re
import json
import sys
import subprocess
from pathlib import Path
from typing import Optional, Dict, Pattern
from collections import defaultdict
from rich.console import Console
from rich.table import Table
import pyfiglet

# ====== Initialization ======
app = typer.Typer()
console = Console()

# ====== Core Configuration ======
CONFIG_FILE = Path.home() / ".logguardian.json"
DEFAULT_PATTERNS = {
    "ssh_bruteforce": re.compile(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", re.IGNORECASE),
    "port_scan": re.compile(r"Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+"),
    "sql_injection": re.compile(r"(\'|--|;|UNION.*SELECT)", re.IGNORECASE),
}
DEFAULT_REMEDIES = {
    "ssh_bruteforce": "1. Block source IP in firewall\n2. Review auth logs\n3. Enable fail2ban",
    "port_scan": "1. Investigate source IP\n2. Check firewall rules\n3. Monitor network",
    "sql_injection": "1. Validate inputs\n2. Use parameterized queries\n3. Check WAF logs",
}

# ====== Helper Functions ======
def show_banner():
    """Display tool banner"""
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]LogGuardian - Security Analyzer v1.0[/bright_yellow]\n")

def load_config() -> Dict:
    """Load configuration with error handling"""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE) as f:
                return json.load(f)
        return {}
    except Exception as e:
        console.print(f"[red]Config error: {str(e)}[/red]")
        return {}

def save_config(data: Dict):
    """Save configuration with error handling"""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        console.print(f"[red]Failed to save config: {str(e)}[/red]")

# ====== Core Analysis Functions ======
def analyze_logs(file_path: Path) -> Dict:
    """Analyze log file with security patterns"""
    results = defaultdict(int)
    patterns = {**DEFAULT_PATTERNS, **load_config().get("patterns", {})}
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                for name, pattern in patterns.items():
                    if pattern.search(line):
                        results[name] += 1
        return dict(results)
    except FileNotFoundError:
        console.print(f"[red]Error: File {file_path} not found[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Analysis failed: {str(e)}[/red]")
        sys.exit(1)

def audit_config(config_path: Path, config_type: str) -> list:
    """Audit configuration files"""
    try:
        with open(config_path, "r") as f:
            content = f.read().lower()
            
        issues = []
        if config_type == "ssh":
            if "permitrootlogin yes" in content:
                issues.append("Insecure: Root login enabled")
            if "passwordauthentication yes" in content:
                issues.append("Insecure: Password auth enabled")
                
        return issues
    
    except Exception as e:
        console.print(f"[red]Audit failed: {str(e)}[/red]")
        sys.exit(1)

# ====== CLI Commands ======
@app.command()
def analyze(
    path: str = typer.Argument(..., help="Log file path"),
    output: str = typer.Option("text", help="Output format (text/json)")
):
    """Analyze log files for security events"""
    show_banner()
    results = analyze_logs(Path(path))
    
    if output == "json":
        console.print(json.dumps(results, indent=2))
    else:
        table = Table(title="Security Analysis Results", show_header=True)
        table.add_column("Event Type", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Recommended Action", style="green")
        
        for event, count in results.items():
            remedy = DEFAULT_REMEDIES.get(event, "Investigate manually")
            table.add_row(event, str(count), remedy)
            
        console.print(table)

@app.command()
def audit(
    config_path: str = typer.Argument(..., help="Path to config file"),
    config_type: str = typer.Argument(..., help="Type: ssh/nginx/apache")
):
    """Audit configuration files for security issues"""
    show_banner()
    issues = audit_config(Path(config_path), config_type)
    
    if issues:
        console.print(f"[red]Found {len(issues)} issues in {config_path}:[/red]")
        for issue in issues:
            console.print(f"  • {issue}")
    else:
        console.print(f"[green]No issues found in {config_path}[/green]")

@app.command()
def update():
    """Update LogGuardian to latest version"""
    show_banner()
    try:
        result = subprocess.run(
            ["git", "pull", "origin", "main"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            console.print("[green]Update successful![/green]")
            console.print(result.stdout)
        else:
            console.print("[red]Update failed:[/red]")
            console.print(result.stderr)
    except Exception as e:
        console.print(f"[red]Update error: {str(e)}[/red]")

@app.command()
def version():
    """Show version information"""
    show_banner()
    console.print("[bold]LogGuardian v1.0[/bold]")
    console.print("Maintained by Blue Team Security")

if __name__ == "__main__":
    app()
