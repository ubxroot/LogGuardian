#!/usr/bin/env python3
"""
LogGuardian - Blue Team Security Analyzer 🔐
"""

import typer
# ... (keep all existing imports and code) ...

@app.callback()
def main():
    """
    LogGuardian - Detect security events & analyze configurations
    Features:
    • Real-time log analysis (SSH brute force, port scans)
    • Security misconfiguration checks
    • Binary file scanning & hash verification
    • Multiple output formats (table, json, html, txt)
    """

# ... (existing analyze/config_check/scan_binary functions remain unchanged) ...

if __name__ == "__main__":
    app()
New Dependencies (requirements.txt):

typer[all]==0.9.0
rich==13.7.1
pyfiglet==0.8.post1
python-magic==0.4.27
cve-bin-tool==4.0
