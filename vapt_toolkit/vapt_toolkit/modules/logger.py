import os
from datetime import datetime

class VAPTLogger:
    def __init__(self):
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)
        self.log_file = f"{self.log_dir}/vapt_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{timestamp}] {message}"
        with open(self.log_file, "a") as f:
            f.write(entry + "\n")

    def view_logs(self):
        print(f"\n[*] Log file: {self.log_file}\n")
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                print(f.read())
        else:
            print("[-] No logs found.")
