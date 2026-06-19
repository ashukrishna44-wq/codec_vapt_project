#!/usr/bin/env python3
"""
VAPT Toolkit - Vulnerability Assessment & Penetration Testing
Author: Ashmit Kumar | CodeAlpha Internship
"""

import sys
import os
from datetime import datetime
from modules.banner import print_banner
from modules.nmap_scanner import NmapScanner
from modules.vuln_scanner import VulnerabilityScanner
from modules.web_tester import WebTester
from modules.report_generator import ReportGenerator
from modules.logger import VAPTLogger

def main_menu():
    print("\n" + "="*55)
    print("          VAPT TOOLKIT - MAIN MENU")
    print("="*55)
    print("  [1] Network Scan (Nmap)")
    print("  [2] Vulnerability Assessment")
    print("  [3] Web Application Testing")
    print("  [4] Generate Report")
    print("  [5] View Logs")
    print("  [0] Exit")
    print("="*55)
    return input("  Select option: ").strip()

def main():
    logger = VAPTLogger()
    report_data = {
        "target": "",
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nmap_results": {},
        "vuln_results": [],
        "web_results": []
    }

    print_banner()

    target = input("\n[*] Enter Target IP / URL (e.g. 192.168.1.1 or http://dvwa.local): ").strip()
    if not target:
        print("[-] No target provided. Exiting.")
        sys.exit(1)

    report_data["target"] = target
    logger.log(f"Session started | Target: {target}")

    while True:
        choice = main_menu()

        if choice == "1":
            scanner = NmapScanner(target, logger)
            results = scanner.run()
            report_data["nmap_results"] = results

        elif choice == "2":
            vuln = VulnerabilityScanner(target, logger)
            results = vuln.run()
            report_data["vuln_results"] = results

        elif choice == "3":
            web = WebTester(target, logger)
            results = web.run()
            report_data["web_results"] = results

        elif choice == "4":
            gen = ReportGenerator(report_data)
            gen.generate()

        elif choice == "5":
            logger.view_logs()

        elif choice == "0":
            print("\n[*] Session ended. Goodbye!\n")
            logger.log("Session ended.")
            sys.exit(0)

        else:
            print("[-] Invalid option. Try again.")

if __name__ == "__main__":
    main()
