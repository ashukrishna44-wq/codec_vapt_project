import socket
import subprocess
import re

# Common CVE mapping for well-known vulnerable services
VULN_DB = {
    "ftp": [
        {"cve": "CVE-2011-2523", "desc": "vsftpd 2.3.4 Backdoor Command Execution", "severity": "CRITICAL"},
        {"cve": "CVE-1999-0497", "desc": "Anonymous FTP Login Allowed", "severity": "MEDIUM"},
    ],
    "ssh": [
        {"cve": "CVE-2018-10933", "desc": "libssh Authentication Bypass", "severity": "CRITICAL"},
        {"cve": "CVE-2016-6515", "desc": "OpenSSH DoS via large password", "severity": "HIGH"},
    ],
    "http": [
        {"cve": "CVE-2017-5638", "desc": "Apache Struts2 Remote Code Execution", "severity": "CRITICAL"},
        {"cve": "CVE-2021-41773", "desc": "Apache Path Traversal (2.4.49)", "severity": "CRITICAL"},
        {"cve": "CVE-2019-0232",  "desc": "Apache Tomcat RCE via CGI Servlet", "severity": "HIGH"},
    ],
    "smb": [
        {"cve": "CVE-2017-0144", "desc": "EternalBlue SMB RCE (MS17-010)", "severity": "CRITICAL"},
        {"cve": "CVE-2020-0796", "desc": "SMBGhost - SMBv3 RCE", "severity": "CRITICAL"},
    ],
    "mysql": [
        {"cve": "CVE-2012-2122", "desc": "MySQL Auth Bypass via Timing Attack", "severity": "HIGH"},
    ],
    "rdp": [
        {"cve": "CVE-2019-0708", "desc": "BlueKeep RDP Pre-Auth RCE", "severity": "CRITICAL"},
        {"cve": "CVE-2012-0002", "desc": "MS12-020 RDP DoS", "severity": "HIGH"},
    ],
    "telnet": [
        {"cve": "CVE-2011-4862", "desc": "FreeBSD Telnet RCE via encrypt_keyid", "severity": "CRITICAL"},
    ],
}

SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[93m",
    "MEDIUM":   "\033[94m",
    "LOW":      "\033[92m",
}
RESET = "\033[0m"

class VulnerabilityScanner:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.findings = []

    def run(self):
        print("\n" + "="*55)
        print("        VULNERABILITY ASSESSMENT")
        print("="*55)

        print("[*] Detecting open ports and services...")
        services = self._detect_services()

        if not services:
            print("[-] No services detected. Run Nmap scan first or check connectivity.")
            return []

        print(f"[+] Detected services: {', '.join(services)}\n")
        self.logger.log(f"Vulnerability scan started | Services: {services}")

        for service in services:
            self._check_vulns(service)

        self._check_default_creds()
        self._run_nmap_scripts()

        print(f"\n[+] Assessment complete. Found {len(self.findings)} potential vulnerabilities.")
        self.logger.log(f"Vulnerability scan complete | {len(self.findings)} findings")
        return self.findings

    def _detect_services(self):
        detected = []
        common_ports = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
            80: "http", 443: "http", 445: "smb", 3306: "mysql",
            3389: "rdp", 8080: "http", 8443: "http"
        }
        clean_target = self.target.replace("http://", "").replace("https://", "").split("/")[0]

        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((clean_target, port))
                if result == 0 and service not in detected:
                    detected.append(service)
                sock.close()
            except:
                pass
        return detected

    def _check_vulns(self, service):
        print(f"[*] Checking vulnerabilities for: {service.upper()}")
        vulns = VULN_DB.get(service, [])
        if not vulns:
            print(f"    [~] No known CVEs mapped for {service}")
            return

        for vuln in vulns:
            color = SEVERITY_COLOR.get(vuln["severity"], "")
            print(f"    {color}[{vuln['severity']}]{RESET} {vuln['cve']} - {vuln['desc']}")
            self.findings.append({
                "service": service,
                "cve": vuln["cve"],
                "description": vuln["desc"],
                "severity": vuln["severity"]
            })

    def _check_default_creds(self):
        print("\n[*] Checking for default credentials on common services...")
        default_creds = [
            ("admin", "admin"),
            ("admin", "password"),
            ("root", "root"),
            ("admin", ""),
        ]
        clean_target = self.target.replace("http://", "").replace("https://", "").split("/")[0]

        # FTP anonymous check
        try:
            import ftplib
            ftp = ftplib.FTP(timeout=3)
            ftp.connect(clean_target, 21)
            ftp.login("anonymous", "anonymous@test.com")
            ftp.quit()
            print("    \033[91m[CRITICAL]\033[0m Anonymous FTP login successful!")
            self.findings.append({
                "service": "ftp",
                "cve": "CVE-1999-0497",
                "description": "Anonymous FTP login enabled",
                "severity": "CRITICAL"
            })
        except:
            print("    [+] FTP anonymous login: Disabled (Good)")

    def _run_nmap_scripts(self):
        print("\n[*] Running Nmap vulnerability scripts (--script vuln)...")
        clean_target = self.target.replace("http://", "").replace("https://", "").split("/")[0]
        try:
            result = subprocess.run(
                ["nmap", "--script", "vuln", "-T4", clean_target],
                capture_output=True, text=True, timeout=180
            )
            output = result.stdout
            if "VULNERABLE" in output:
                print("\033[91m[!] Nmap vuln scripts found vulnerabilities:\033[0m")
                for line in output.splitlines():
                    if "VULNERABLE" in line or "CVE" in line:
                        print(f"    {line}")
                self.findings.append({
                    "service": "nmap-script",
                    "cve": "See raw output",
                    "description": "Nmap vuln scripts detected issues",
                    "severity": "HIGH"
                })
            else:
                print("    [+] Nmap vuln scripts: No critical issues detected.")
        except FileNotFoundError:
            print("    [-] Nmap not found. Skipping script scan.")
        except subprocess.TimeoutExpired:
            print("    [-] Nmap script scan timed out.")
        except Exception as e:
            print(f"    [-] Error: {e}")
