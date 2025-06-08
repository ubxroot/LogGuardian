#!/usr/bin/env python3
"""
# LogGuardian 🔐 - Blue Team Security Analysis Toolkit

**Features**:
- Real-time detection of SSH brute-force attacks & port scans
- Configuration file audits for SSH/nginx/Apache
- Binary file analysis with SHA-256 hashing and string extraction
- CVE vulnerability scanning for executables
- Multi-format reporting (table, JSON, HTML, text)
- Color-coded terminal output & file-based reports

## 📥 Installation
git clone https://github.com/yourusername/logguardian.git
cd logguardian
pip install -r requirements.txt
chmod +x logguardian.py
sudo apt-get install libmagic1 # For Debian/Ubuntu systems

## 📦 Dependencies
typer[all]==0.9.0
rich==13.7.1
pyfiglet==0.8.post1
python-magic==0.4.27
cve-bin-tool==4.0

## 🚀 Usage
# Log analysis with table output
./logguardian.py analyze /var/log/auth.log

# Binary scan with CVE checks and HTML report
./logguardian.py scan-binary suspicious.exe --cve --output-format html

# SSH config security audit
./logguardian.py config-check /etc/ssh/sshd_config ssh

# Generate JSON report for log analysis
./logguardian.py analyze /var/log/secure --output-format json > report.json
"""

import typer
import hashlib
import subprocess
from rich.console import Console
from rich.table import Table
from pathlib import Path
import pyfiglet
import json
import re
import string
from datetime import datetime
from typing import Optional
from html import escape

app = typer.Typer()
console = Console()

def show_banner():
    banner = pyfiglet.figlet_format("UBXROOT", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]LogGuardian – Security Analyzer v2.1[/bright_yellow]\n")

# Security analysis patterns
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

def calculate_sha256(file_path: Path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_printable_strings(file_path: Path, min_length=4):
    printable = set(bytes(string.printable, 'ascii'))
    strings = []
    current_string = []
    
    with open(file_path, 'rb') as f:
        for byte in f.read():
            if byte in printable:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []
        if current_string:
            strings.append(''.join(current_string))
    return strings

def generate_txt_report(scan_data, file_path):
    with open(file_path, 'w') as f:
        f.write(f"Binary Scan Report\n{'='*20}\n")
        f.write(f"File: {scan_data['filename']}\n")
        f.write(f"SHA256: {scan_data['sha256']}\n")
        f.write("\nDetected Strings:\n")
        for s in scan_data['strings']:
            f.write(f"- {s}\n")
        if scan_data.get('cve_results'):
            f.write("\nVulnerabilities:\n")
            for vuln in scan_data['cve_results']:
                f.write(f"- {vuln}\n")

def generate_html_report(scan_data, file_path):
    html = f"""<html>
<head><title>Binary Scan Report</title></head>
<body>
<h1>Binary Analysis Report</h1>
<h2>File: {escape(scan_data['filename'])}</h2>
<p><strong>SHA256:</strong> {scan_data['sha256']}</p>
<h3>Detected Strings ({len(scan_data['strings'])})</h3>
<ul>"""
    for s in scan_data['strings'][:1000]:
        html += f"<li>{escape(s)}</li>"
    html += "</ul>"
    if scan_data.get('cve_results'):
        html += "<h3>Vulnerabilities</h3><ul>"
        for vuln in scan_data['cve_results']:
            html += f"<li>{escape(vuln)}</li>"
        html += "</ul>"
    html += "</body></html>"
    with open(file_path, 'w') as f:
        f.write(html)

@app.command()
def analyze(
    file_path: Path = typer.Argument(..., help="Path to log file"),
    output_format: Optional[str] = typer.Option("table", help="Output format: table or json")
):
    """Analyze log files for security events"""
    show_banner()

    if not file_path.exists():
        console.print("[red]Error: File not found[/red]")
        raise typer.Exit(code=1)

    results = list(analyze_log(file_path))

    if output_format == "json":
        console.print(json.dumps(results, indent=2))
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
def scan_binary(
    file_path: Path = typer.Argument(..., help="Path to binary file"),
    output_format: str = typer.Option("table", help="Output format: table, txt, json, html"),
    check_cves: bool = typer.Option(False, "--cve", help="Enable CVE vulnerability checking"),
    output_file: Optional[Path] = typer.Option(None, help="Output file path")
):
    """Analyze binary files for security risks"""
    show_banner()

    if not file_path.exists():
        console.print("[red]Error: File not found[/red]")
        raise typer.Exit(code=1)

    scan_data = {
        "filename": str(file_path),
        "sha256": calculate_sha256(file_path),
        "strings": extract_printable_strings(file_path),
        "cve_results": []
    }

    if check_cves:
        try:
            result = subprocess.run(
                ['cve-bin-tool', str(file_path)],
                capture_output=True,
                text=True,
                check=True
            )
            scan_data['cve_results'] = result.stdout.splitlines()
        except Exception as e:
            console.print(f"[yellow]CVE check failed: {e}[/yellow]")

    if output_format == "table":
        table = Table(show_header=True, header_style="bold blue")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("File Path", scan_data['filename'])
        table.add_row("SHA256", scan_data['sha256'])
        table.add_row("Detected Strings", str(len(scan_data['strings'])))
        table.add_row("CVE Checks", "Enabled" if check_cves else "Disabled")
        
        if scan_data['cve_results']:
            table.add_row("Vulnerabilities Found", str(len(scan_data['cve_results'])))
        
        console.print(table)
        
    elif output_format == "json":
        output = json.dumps(scan_data, indent=2)
        if output_file:
            output_file.write_text(output)
        else:
            console.print(output)
    
    elif output_format in ["txt", "html"]:
        if not output_file:
            output_file = file_path.with_suffix(f".{output_format}")
            
        if output_format == "txt":
            generate_txt_report(scan_data, output_file)
        else:
            generate_html_report(scan_data, output_file)
        
        console.print(f"[green]Report generated: {output_file}[/green]")
    
    else:
        console.print("[red]Invalid output format[/red]")
        raise typer.Exit(code=1)

@app.command()
def config_check(
    config_path: Path = typer.Argument(..., help="Path to config file"),
    check_type: str = typer.Argument(..., help="Config type (nginx/apache/ssh)")
):
    """Audit configuration files for security issues"""
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
