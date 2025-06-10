#!/usr/bin/env python3
\"\"\"
LogGuardian - Blue Team Security Analyzer 🔐
Advanced log analysis and security monitoring toolkit
\"\"\"

import typer
import re
import json
import sys
import gzip
import ipaddress
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict
from collections import defaultdict
import geoip2.database
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import track
import pyfiglet
import magic

app = typer.Typer()
console = Console()

# Configuration
CONFIG_FILE = Path.home() / ".logguardian_config.json"
GEOIP_DB_PATH = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
THREAT_INTEL_API = "https://api.threatintel.com/v1/check/ip/"
HASH_LOOKUP_API = "https://api.threatintel.com/v1/check/hash/"

ALERT_LOG = Path("logguardian_alerts.txt")

class LogAnalyzer:
    def __init__(self):
        self.patterns = self.load_security_patterns()
        self.stats = defaultdict(lambda: defaultdict(int))
        self.geoip_reader = None
        self.threat_cache = {}

        if GEOIP_DB_PATH.exists():
            try:
                self.geoip_reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
            except Exception as e:
                console.print(f"[yellow]⚠️ GeoIP error: {str(e)}[/yellow]")

    def load_security_patterns(self) -> Dict[str, re.Pattern]:
        return {
            'xss': re.compile(r'<script.*?>.*?</script>', re.IGNORECASE),
            'sqli': re.compile(r'(\'|--|;|UNION.*SELECT)', re.IGNORECASE),
            'lfi': re.compile(r'(\.\./|\.\\|etc/passwd)', re.IGNORECASE),
            'rce': re.compile(r'(/bin/sh|cmd\.exe|\|bash)', re.IGNORECASE),
            'bruteforce': re.compile(r'Failed password for', re.IGNORECASE),
            'port_scan': re.compile(r'Connection reset by (\\d+\\.\\d+\\.\\d+\\.\\d+) port \\d+'),
            'cve': re.compile(r'CVE-\\d{4}-\\d{4,7}', re.IGNORECASE)
        }

    def analyze_file(self, file_path: Path, realtime: bool = False):
        open_func = gzip.open if file_path.suffix == '.gz' else open

        if not file_path.is_file():
            return

        if self.is_binary(file_path):
            self.scan_binary(file_path)
            return

        with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in track(f, description=f"Analyzing {file_path.name}..."):
                self.process_line(line.strip())
                if realtime:
                    pass  # Extend with socket/pipe monitoring if needed

    def is_binary(self, path: Path) -> bool:
        try:
            return 'text' not in magic.from_file(str(path), mime=True)
        except:
            return False

    def scan_binary(self, file_path: Path):
        with open(file_path, 'rb') as f:
            data = f.read()
            file_hash = hashlib.sha256(data).hexdigest()
            console.print(f"[blue]🔍 Scanning binary file: {file_path.name}[/blue]")
            console.print(f"[cyan]Hash (SHA256):[/cyan] {file_hash}")

            if self.check_hash_malware(file_hash):
                self.stats['security']['malware_binary'] += 1
                self.log_alert("malware_binary", f"Malicious binary detected: {file_path} - {file_hash}")

    def process_line(self, line: str):
        self.stats['general']['total_lines'] += 1

        for pattern_name, pattern in self.patterns.items():
            if pattern.search(line):
                self.stats['security'][pattern_name] += 1
                self.log_alert(pattern_name, line)

        ips = re.findall(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', line)
        for ip in ips:
            if self.is_valid_ip(ip):
                self.process_ip(ip)

    def process_ip(self, ip: str):
        self.stats['ips'][ip] += 1

        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                self.stats['geo'][response.country.iso_code] += 1
            except:
                pass

        if ip not in self.threat_cache:
            self.threat_cache[ip] = self.check_threat_intel(ip)

        if self.threat_cache[ip]:
            self.stats['security']['malicious_ips'] += 1
            self.log_alert("malicious_ip", f"Threat IP: {ip}")

    def is_valid_ip(self, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def check_threat_intel(self, ip: str) -> bool:
        try:
            response = requests.get(f"{THREAT_INTEL_API}{ip}", timeout=3)
            return response.json().get('malicious', False)
        except:
            return False

    def check_hash_malware(self, file_hash: str) -> bool:
        try:
            response = requests.get(f"{HASH_LOOKUP_API}{file_hash}", timeout=3)
            return response.json().get('malicious', False)
        except:
            return False

    def log_alert(self, event_type: str, detail: str):
        console.print(f"[red]🚨 {event_type.upper()} detected[/red]")
        console.print(f"   [white]{detail}[/white]\\n")
        with ALERT_LOG.open("a") as logf:
            logf.write(f"[{datetime.now().isoformat()}] {event_type.upper()}: {detail}\\n")

class Reporter:
    @staticmethod
    def generate_text_report(analyzer: LogAnalyzer) -> str:
        report = [
            "LogGuardian Security Report",
            "=" * 40,
            f"Timestamp: {datetime.now().isoformat()}",
            f"Total lines processed: {analyzer.stats['general']['total_lines']}",
            "\\nSecurity Events:"
        ]
        for category, count in analyzer.stats['security'].items():
            report.append(f"- {category.replace('_', ' ').title()}: {count}")
        return "\\n".join(report)

    @staticmethod
    def generate_json_report(analyzer: LogAnalyzer) -> str:
        return json.dumps(analyzer.stats, indent=2)

    @staticmethod
    def display_live_table(analyzer: LogAnalyzer):
        table = Table(title="Live Security Overview", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        for category, count in analyzer.stats['security'].items():
            table.add_row(category.title(), str(count))
        console.print(table)

@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Path to log file/directory"),
    output_format: str = typer.Option("text", help="Output format (text/json)"),
    realtime: bool = typer.Option(False, "--realtime", help="Enable real-time mode"),
    geoip: bool = typer.Option(True, help="Enable GeoIP lookups")
):
    show_banner()
    analyzer = LogAnalyzer()
    if log_path.is_dir():
        for file in log_path.glob("*"):
            analyzer.analyze_file(file, realtime)
    else:
        analyzer.analyze_file(log_path, realtime)

    if output_format == "json":
        console.print(Reporter.generate_json_report(analyzer))
    else:
        console.print(Reporter.generate_text_report(analyzer))
    Reporter.display_live_table(analyzer)

@app.command()
def update():
    show_banner()
    console.print("🔄 Checking for updates...")
    try:
        result = subprocess.run(['git', 'pull', 'origin', 'main'], check=True, capture_output=True, text=True)
        console.print(f"[green]✅ Update successful![/green]\\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Update failed:[/red]\\n{e.stderr}")

@app.command()
def patterns():
    show_banner()
    analyzer = LogAnalyzer()
    table = Table(title="Active Detection Patterns", show_header=True, header_style="bold blue")
    table.add_column("Name", style="cyan")
    table.add_column("Regex", style="magenta")
    for name, pattern in analyzer.patterns.items():
        table.add_row(name.upper(), pattern.pattern)
    console.print(table)

def show_banner():
    art = pyfiglet.figlet_format("ubxroot", font="slant")
    console.print(f"[bright_red]{art}[/bright_red]")
    console.print("[bright_yellow]LogGuardian - Blue Team Security Analyzer v2.5[/bright_yellow]\\n")

if __name__ == "__main__":
    app()
"""

with open("/mnt/data/logguardian.py", "w") as f:
    f.write(updated_code)

"/mnt/data/logguardian.py"

