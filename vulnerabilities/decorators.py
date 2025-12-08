from vulnerabilities.vulnerability import Vulnerability

class VulnDecorator(Vulnerability):
    
    def __init__(self, wrapped):
        self.wrapped = wrapped
    
    def get_severity(self):
        return self.wrapped.get_severity()
    
    def get_title(self):
        return self.wrapped.get_title()
    
    def get_remediation(self):
        return self.wrapped.get_remediation()

    # --- CORRECTION ICI ---
    # Permet d'accéder à .detail et .solution à travers le décorateur
    def __getattr__(self, name):
        return getattr(self.wrapped, name)


class CriticalContextDecorator(VulnDecorator):
    
    def __init__(self, wrapped, reason):
        super().__init__(wrapped)
        self.reason = reason
    
    def get_severity(self):
        # On plafonne à 100 pour éviter des scores de 120
        return min(100, self.wrapped.get_severity() + 20)
    
    def get_title(self):
        return f"{self.wrapped.get_title()} [CRITIQUE: {self.reason}]"