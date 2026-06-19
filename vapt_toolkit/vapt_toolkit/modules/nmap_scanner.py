import subprocess
import json
import re

class NmapScanner:
    def __init__(self, target, logger):
        self.target = target
        self.logger = logger
        self.results = {}

    def run(self):
        print("\n" + "="*55)
        print("          NETWORK SCAN - NMAP")
        print("="*55)
        print("  [1] Quick Scan        (-T4 -F)")
        print("  [2] Full Port Scan    (-p- -T4)")
        print("  [3] Service & OS Scan (-sV -O)")
        print("  [4] Aggressive Scan   (-A)")
        print("  [5] Stealth Scan      (-sS)")
        print("="*55)
        choice = input("  Select scan type: ").strip()

        scan_map = {
            "1": ("-T4 -F", "Quick Scan"),
            "2": ("-p- -T4", "Full Port Scan"),
            "3": ("-sV -O", "Service & OS Detection"),
            "4": ("-A", "Aggressive Scan"),
            "5": ("-sS", "Stealth SYN Scan"),
        }

        if choice not in scan_map:
            print("[-] Invalid choice.")
            return {}

        flags, scan_name = scan_map[choice]
        print(f"\n[*] Starting {scan_name} on {self.target}...")
        self.logger.log(f"Nmap {scan_name} started on {self.target}")

        try:
            cmd = f"nmap {flags} {self.target}"
            result = subprocess.run(
                cmd.split(),
                capture_output=True,
                text=True,
                timeout=300
            )
            output = result.stdout
            print("\n" + output)
            self.results = self._parse_output(output, scan_name)
            self.logger.log(f"Nmap {scan_name} completed.")
            print(f"[+] Scan complete. Found {len(self.results.get('open_ports', []))} open port(s).")
            return self.results

        except FileNotFoundError:
            print("[-] Nmap not found. Install with: sudo apt install nmap")
            self.logger.log("ERROR: Nmap not installed.")
            return {}
        except subprocess.TimeoutExpired:
            print("[-] Scan timed out.")
            return {}
        except Exception as e:
            print(f"[-] Scan error: {e}")
            return {}

    def _parse_output(self, output, scan_name):
        parsed = {
            "scan_type": scan_name,
            "target": self.target,
            "open_ports": [],
            "raw_output": output
        }

        port_pattern = re.compile(r'(\d+)/tcp\s+(open)\s+(\S+)(?:\s+(.*))?')
        for match in port_pattern.finditer(output):
            parsed["open_ports"].append({
                "port": match.group(1),
                "state": match.group(2),
                "service": match.group(3),
                "version": match.group(4) or ""
            })

        os_match = re.search(r'OS details: (.+)', output)
        if os_match:
            parsed["os_detected"] = os_match.group(1)

        return parsed
