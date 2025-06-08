#!/usr/bin/env python3

import typer
from rich.console import Console
from rich.table import Table
from pathlib import Path
import pyfiglet
import yaml
import re
from datetime import datetime
from typing import Optional

app = typer.Typer()
console = Console()

# Display UBXROOT banner
def show_banner():
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]LogGuardian – Blue Team Log Analyzer v1.0[/bright_yellow]\n")

# Sample detection rules
RULES = {
    "bruteforce": {
        "pattern": r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)",
        "description": "SSH brute force attempt detected",
        "severity": "HIGH"
    },
    "port_scan": {
        "pattern": r"Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+",
        "description": "Possible port scanning activity",
        "severity": "MEDIUM"
    }
}

def analyze_log(file_path: Path):
    try:
        with open(file_path, 'r') as f:
            for line in f:
                for rule_name, rule in RULES.items():
                    match = re.search(rule['pattern'], line)
                    if match:
                        yield {
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "event_type": rule_name,
                            "description": rule['description'],
                            "severity": rule['severity'],
                            "source_ip": match.group(1),
                            "raw_line": line.strip()
                        }
    except Exception as e:
        console.print(f"[red]Error reading file: {e}[/red]")
        raise typer.Exit(code=1)

@app.command()
def analyze(
    file_path: Path = typer.Argument(..., help="Path to log file"),
    output_format: Optional[str] = typer.Option("table", help="Output format: table or json")
):
    show_banner()

    if not file_path.exists():
        console.print("[red]Error: File not found[/red]")
        raise typer.Exit(code=1)

    results = list(analyze_log(file_path))

    if output_format == "json":
        console.print(results)
    else:
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Timestamp", width=20)
        table.add_column("Event Type", width=15)
        table.add_column("Description", width=50)
        table.add_column("Severity", width=12)
        table.add_column("Source IP", width=15)

        for event in results:
            severity_color = "red" if event["severity"] == "HIGH" else "yellow"
            table.add_row(
                event["timestamp"],
                event["event_type"],
                event["description"],
                f"[{severity_color}]{event['severity']}[/{severity_color}]",
                event["source_ip"]
            )

        console.print(table)
        console.print(f"\n[bright_green]Analysis complete. Found {len(results)} security events.[/bright_green]")

@app.command()
def config_check(
    config_path: Path = typer.Argument(..., help="Path to config file"),
    check_type: str = typer.Argument(..., help="Config type (nginx/apache/ssh)")
):
    show_banner()

    try:
        with open(config_path, 'r') as f:
            config_content = f.read()

            if check_type == "ssh":
                if "PermitRootLogin yes" in config_content:
                    console.print("[red]ALERT: SSH root login enabled[/red]")
                if "PasswordAuthentication yes" in config_content:
                    console.print("[red]ALERT: Password authentication enabled[/red]")

    except Exception as e:
        console.print(f"[red]Error reading config file: {e}[/red]")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()
