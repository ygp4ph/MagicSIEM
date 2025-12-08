from typing import List
from strategies.base import IScanStrategy
from core.alert_system import AlertSystem
from vulnerabilities.base import Vulnerability
from vulnerabilities.decorators import CriticalContextDecorator

class PDF:
    def __init__(self, content):
        self.content = content
    
    def __str__(self):
        return f"\n[Rapport PDF Généré] : {self.content}"

class Scanner:
    def __init__(self):
        self.strategy: IScanStrategy = None
        self.alert_system = AlertSystem()
        self.findings: List[Vulnerability] = []
        self.critical_contexts: List[str] = []
        
        self.alert_system.configure("admin@default.com")

    def set_strategy(self, strategy: IScanStrategy):
        self.strategy = strategy

    def add_critical_context(self, context: str):
        self.critical_contexts.append(context)

    def run_scan(self):
        if not self.strategy:
            return
        
        raw_findings = self.strategy.scan()
        
        for v in raw_findings:
            final_vuln = v
            for context in self.critical_contexts:
                final_vuln = CriticalContextDecorator(final_vuln, context)
            
            self.findings.append(final_vuln)
            self.alert_system.send_alert(final_vuln)

    def generate_report(self) -> PDF:
        total_risk = sum(v.get_severity() for v in self.findings)
        report_content = (
            f"Analyse terminée.\n"
            f"   - Vulnérabilités trouvées : {len(self.findings)}\n"
            f"   - Score de risque total : {total_risk}"
        )
        return PDF(report_content)