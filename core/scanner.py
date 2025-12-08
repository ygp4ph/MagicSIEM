from core.alert_system import AlertSystem
from vulnerabilities.decorators import CriticalContextDecorator

class Scanner:
    
    def __init__(self):
        self.strategy = None
        self.alert_system = AlertSystem()
        self.findings = []
        self.critical_contexts = [] # ex: Production, Public, etc.
        self.alert_system.configure("admin@local")
    
    def set_strategy(self, strategy):
        self.strategy = strategy
    
    def add_critical_context(self, context):
        if context not in self.critical_contexts:
            self.critical_contexts.append(context)
            
    def reset(self):
        # Vide les resultats precedents pour eviter les doublons
        self.findings = []
    
    def run_scan(self):
        if not self.strategy:
            return
        
        raw_results = self.strategy.scan()
        
        for vuln in raw_results:
            final_vuln = vuln
            # Pattern Decorator: on applique les contextes
            for ctx in self.critical_contexts:
                final_vuln = CriticalContextDecorator(final_vuln, ctx)
            
            self.findings.append(final_vuln)
            # Pattern Observer: on notifie
            self.alert_system.send_alert(final_vuln)

    def get_stats(self):
        return {
            'count': len(self.findings),
            'critical': sum(1 for v in self.findings if v.get_severity() >= 90),
            'high': sum(1 for v in self.findings if 70 <= v.get_severity() < 90),
            'medium': sum(1 for v in self.findings if 50 <= v.get_severity() < 70)
        }