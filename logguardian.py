#!/usr/bin/env python3
"""
LogGuardian - Blue Team Security Analyzer 🔐
Advanced log analysis and security monitoring toolkit
"""

import typer
import re
import json
import sys
import gzip
import ipaddress
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
import hashlib

app = typer.Typer()
console = Console()

# Configuration
CONFIG_FILE = Path.home() / ".logguardian_config.json"
GEOIP_DB_PATH = Path("/usr/share/GeoIP/GeoLite2-City.mmdb")
THREAT_INTEL_API = "https://api.threatintel.com/v1/check/ip/"

class LogAnalyzer:
    """Core log analysis engine with security focus"""
    
    def __init__(self):
        self.patterns = self.load_security_patterns()
        self.stats = defaultdict(lambda: defaultdict(int))
        self.geoip_reader = None
        self.threat_cache = {}
        
        if GEOIP_DB_PATH.exists():
            try:
                self.geoip_reader = geoip2.database.Reader(str(GEOIP_DB_PATH))
            except Exception as e:
                console.print(f"[yellow]⚠️ GeoIP database error: {str(e)}[/yellow]")

    def load_security_patterns(self) -> Dict[str, re.Pattern]:
        """Load security detection patterns"""
        return {
            'xss': re.compile(r'<script.*?>.*?</script>', re.IGNORECASE),
            'sqli': re.compile(r'(\'|--|;|UNION.*SELECT)', re.IGNORECASE),
            'lfi': re.compile(r'(\.\./|\.\\|etc/passwd)', re.IGNORECASE),
            'rce': re.compile(r'(/bin/sh|cmd\.exe|\|bash)', re.IGNORECASE),
            'bruteforce': re.compile(r'Failed password for', re.IGNORECASE),
            'port_scan': re.compile(r'Connection reset by (\d+\.\d+\.\d+\.\d+) port \d+'),
            'cve': re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
        }

    def analyze_file(self, file_path: Path, realtime: bool = False):
        """Analyze log file with security patterns"""
        open_func = gzip.open if file_path.suffix == '.gz' else open
        
        with open_func(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
            for line in track(f, description="Analyzing logs..."):
                self.process_line(line.strip())
                
                if realtime:
                    # Implement real-time processing logic
                    pass

    def process_line(self, line: str):
        """Process individual log line"""
        # Basic statistics
        self.stats['general']['total_lines'] += 1
        
        # Security analysis
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(line):
                self.stats['security'][pattern_name] += 1
                self.log_security_event(pattern_name, line)
                
        # IP analysis
        ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
        for ip in ips:
            if self.is_valid_ip(ip):
                self.process_ip(ip)

    def process_ip(self, ip: str):
        """Analyze IP address for threats"""
        self.stats['ips'][ip] += 1
        
        # Geolocation lookup
        if self.geoip_reader:
            try:
                response = self.geoip_reader.city(ip)
                self.stats['geo'][response.country.iso_code] += 1
            except:
                pass
        
        # Threat intelligence check
        if ip not in self.threat_cache:
            self.threat_cache[ip] = self.check_threat_intel(ip)
            
        if self.threat_cache[ip]:
            self.stats['security']['malicious_ips'] += 1

    def check_threat_intel(self, ip: str) -> bool:
        """Check IP against threat intelligence feed"""
        try:
            response = requests.get(f"{THREAT_INTEL_API}{ip}", timeout=3)
            return response.json().get('malicious', False)
        except Exception as e:
            return False

    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def log_security_event(self, event_type: str, line: str):
        """Log security events with alerts"""
        console.print(f"[red]🚨 ALERT: {event_type.upper()} detected[/red]")
        console.print(f"   [white]{line}[/white]\n")

class Reporter:
    """Reporting and output generation"""
    
    @staticmethod
    def generate_text_report(analyzer: LogAnalyzer) -> str:
        """Generate text format report"""
        report = [
            "LogGuardian Security Report",
            "=" * 40,
            f"Analysis timestamp: {datetime.now().isoformat()}",
            f"Total lines processed: {analyzer.stats['general']['total_lines']}",
            "\nSecurity Findings:"
        ]
        
        for category, count in analyzer.stats['security'].items():
            report.append(f"- {category.replace('_', ' ').title()}: {count}")
            
        return "\n".join(report)

    @staticmethod
    def generate_json_report(analyzer: LogAnalyzer) -> str:
        """Generate JSON format report"""
        return json.dumps(analyzer.stats, indent=2)

    @staticmethod
    def display_live_table(analyzer: LogAnalyzer):
        """Display live analysis results in rich table"""
        table = Table(title="Live Security Analysis", show_header=True, header_style="bold magenta")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="green")
        
        for category, count in analyzer.stats['security'].items():
            table.add_row(category.title(), str(count))
            
        console.print(table)

# CLI Commands ----------------------------------------------------------------

@app.command()
def analyze(
    log_path: Path = typer.Argument(..., help="Path to log file/directory"),
    output_format: str = typer.Option("text", help="Output format (text/json)"),
    realtime: bool = typer.Option(False, "--realtime", help="Enable real-time monitoring"),
    geoip: bool = typer.Option(False, help="Enable GeoIP lookups")
):
    """Analyze log files for security threats"""
    show_banner()
    
    analyzer = LogAnalyzer()
    
    if log_path.is_dir():
        for log_file in log_path.glob("*.log*"):
            analyzer.analyze_file(log_file, realtime)
    else:
        analyzer.analyze_file(log_path, realtime)
    
    if output_format == "json":
        console.print(Reporter.generate_json_report(analyzer))
    else:
        console.print(Reporter.generate_text_report(analyzer))
        
    Reporter.display_live_table(analyzer)

@app.command()
def update():
    """Update LogGuardian to latest version"""
    show_banner()
    console.print("🔄 Checking for updates...")
    
    try:
        result = subprocess.run(['git', 'pull', 'origin', 'main'], 
                              check=True, capture_output=True, text=True)
        console.print(f"[green]✅ Update successful![/green]\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        console.print(f"[red]❌ Update failed:[/red]\n{e.stderr}")

@app.command()
def patterns():
    """View current security detection patterns"""
    show_banner()
    analyzer = LogAnalyzer()
    
    table = Table(title="Active Security Patterns", show_header=True, header_style="bold blue")
    table.add_column("Pattern Name", style="cyan")
    table.add_column("Regular Expression", style="magenta")
    
    for name, pattern in analyzer.patterns.items():
        table.add_row(name.upper(), pattern.pattern)
        
    console.print(table)

def show_banner():
    """Display ASCII art banner"""
    banner = pyfiglet.figlet_format("LogGuardian", font="slant")
    console.print(f"[bright_cyan]{banner}[/bright_cyan]")
    console.print("[bright_yellow]Blue Team Security Analyzer v2.0[/bright_yellow]\n")

if __name__ == "__main__":
    app()
