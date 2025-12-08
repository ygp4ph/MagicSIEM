from .base import Vulnerability

class VulnDecorator(Vulnerability):
    def __init__(self, wrapped: Vulnerability):
        self.wrapped = wrapped

    def get_severity(self) -> int:
        return self.wrapped.get_severity()
    def get_title(self) -> str: return self.wrapped.get_title()
    def get_remediation(self) -> str: return self.wrapped.get_remediation()

class CriticalContextDecorator(VulnDecorator):
    def __init__(self, wrapped: Vulnerability, reason: str):
        super().__init__(wrapped)
        self.reason = reason

    def get_severity(self) -> int:
        return super().get_severity() + 20

    def get_title(self) -> str:
        return f"{super().get_title()} [CRITICAL: {self.reason}]"