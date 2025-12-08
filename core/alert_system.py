from vulnerabilities.base import Vulnerability

class AlertSystem:
    def configure(self, email: str):
        self.admin_email = email
        print(f"System configured for {email}")

    def send_alert(self, v: Vulnerability):
        print(f"ALERT: Found {v.get_title()} (Sev: {v.get_severity()})")