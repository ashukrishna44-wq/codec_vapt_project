import os
import json
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

class ReportGenerator:
    def __init__(self, data):
        self.data = data
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = "reports"
        os.makedirs(self.report_dir, exist_ok=True)

    def generate(self):
        print("\n[*] Generating VAPT Report...")
        print("  [1] Text Report (.txt)")
        print("  [2] JSON Report (.json)")
        print("  [3] Both")
        choice = input("  Select format: ").strip()

        if choice in ("1", "3"):
            self._generate_text()
        if choice in ("2", "3"):
            self._generate_json()

    def _generate_text(self):
        filename = f"{self.report_dir}/vapt_report_{self.timestamp}.txt"
        all_findings = self.data.get("vuln_results", []) + self.data.get("web_results", [])
        sorted_findings = sorted(all_findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","LOW"), 3))

        with open(filename, "w") as f:
            f.write("=" * 60 + "\n")
            f.write("   VAPT REPORT - VULNERABILITY ASSESSMENT\n")
            f.write("=" * 60 + "\n")
            f.write(f"  Target      : {self.data.get('target', 'N/A')}\n")
            f.write(f"  Scan Date   : {self.data.get('scan_time', 'N/A')}\n")
            f.write(f"  Author      : Ashmit Kumar | CodeAlpha Internship\n")
            f.write("=" * 60 + "\n\n")

            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            critical = sum(1 for x in all_findings if x.get("severity") == "CRITICAL")
            high     = sum(1 for x in all_findings if x.get("severity") == "HIGH")
            medium   = sum(1 for x in all_findings if x.get("severity") == "MEDIUM")
            low      = sum(1 for x in all_findings if x.get("severity") == "LOW")
            f.write(f"  Total Findings : {len(all_findings)}\n")
            f.write(f"  CRITICAL       : {critical}\n")
            f.write(f"  HIGH           : {high}\n")
            f.write(f"  MEDIUM         : {medium}\n")
            f.write(f"  LOW            : {low}\n\n")

            # Nmap Results
            nmap = self.data.get("nmap_results", {})
            if nmap:
                f.write("NETWORK SCAN RESULTS\n")
                f.write("-" * 40 + "\n")
                f.write(f"  Scan Type : {nmap.get('scan_type', 'N/A')}\n")
                ports = nmap.get("open_ports", [])
                f.write(f"  Open Ports: {len(ports)}\n")
                for p in ports:
                    f.write(f"    Port {p['port']}/tcp  |  {p['service']}  |  {p['version']}\n")
                if nmap.get("os_detected"):
                    f.write(f"  OS Detected: {nmap['os_detected']}\n")
                f.write("\n")

            # Findings
            f.write("VULNERABILITY FINDINGS\n")
            f.write("-" * 40 + "\n")
            if not sorted_findings:
                f.write("  No vulnerabilities found.\n")
            for i, finding in enumerate(sorted_findings, 1):
                f.write(f"\n  [{i}] Severity : {finding.get('severity','N/A')}\n")
                f.write(f"      Type     : {finding.get('type', finding.get('cve','N/A'))}\n")
                f.write(f"      Detail   : {finding.get('description', finding.get('detail', finding.get('payload','N/A')))}\n")
                f.write(f"      Service  : {finding.get('service','N/A')}\n")

            # Recommendations
            f.write("\n\nRECOMMENDATIONS\n")
            f.write("-" * 40 + "\n")
            f.write("  1. Patch all CRITICAL and HIGH severity vulnerabilities immediately.\n")
            f.write("  2. Disable unnecessary services (FTP, Telnet, SMBv1).\n")
            f.write("  3. Implement Web Application Firewall (WAF) for SQL/XSS protection.\n")
            f.write("  4. Add security headers: CSP, HSTS, X-Frame-Options.\n")
            f.write("  5. Change all default credentials on services.\n")
            f.write("  6. Regularly update and patch all software components.\n")
            f.write("  7. Conduct regular penetration testing every quarter.\n")

            f.write("\n" + "=" * 60 + "\n")
            f.write("  END OF REPORT\n")
            f.write("=" * 60 + "\n")

        print(f"[+] Text report saved: {filename}")

    def _generate_json(self):
        filename = f"{self.report_dir}/vapt_report_{self.timestamp}.json"
        report = {
            "report_metadata": {
                "target": self.data.get("target"),
                "scan_date": self.data.get("scan_time"),
                "author": "Ashmit Kumar",
                "internship": "CodeAlpha"
            },
            "nmap_results": self.data.get("nmap_results", {}),
            "vulnerability_findings": self.data.get("vuln_results", []),
            "web_findings": self.data.get("web_results", []),
            "total_findings": len(self.data.get("vuln_results", []) + self.data.get("web_results", []))
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
        print(f"[+] JSON report saved: {filename}")
