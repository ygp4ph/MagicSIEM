from .base import Vulnerability

class BasicVulnerability(Vulnerability):
    def __init__(self, cve_code: str, base_score: int):
        self.cve_code = cve_code
        self.base_score = base_score

    def get_severity(self) -> int:
        return self.base_score

    def get_title(self) -> str:
        return f"Vulnerability {self.cve_code}"

    def get_remediation(self) -> str:
        return f"Apply patch for {self.cve_code}"