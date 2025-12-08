import logging
from core.alert_system import AlertSystem
from vulnerabilities.decorators import CriticalContextDecorator

logger = logging.getLogger(__name__)

class Scanner:
    
    def __init__(self):
        self.strategy = None
        self.alert_system = AlertSystem()
        self.findings = []
        self.critical_contexts = []
        
        self.alert_system.configure("admin@company.com")
        logger.info("Scanner initialise")
    
    def set_strategy(self, strategy):
        self.strategy = strategy
        logger.info(f"Strategie definie: {strategy.__class__.__name__}")
    
    def add_critical_context(self, context):
        self.critical_contexts.append(context)
        logger.info(f"Contexte critique ajoute: {context}")
    
    def run_scan(self):
        if not self.strategy:
            logger.error("Aucune strategie definie")
            return
        
        logger.info("Debut du scan")
        raw_findings = self.strategy.scan()
        
        for vuln in raw_findings:
            final_vuln = vuln
            
            for context in self.critical_contexts:
                final_vuln = CriticalContextDecorator(final_vuln, context)
            
            self.findings.append(final_vuln)
            self.alert_system.send_alert(final_vuln)
        
        logger.info(f"Scan termine: {len(self.findings)} vulnerabilites stockees")
    
    def generate_report(self):
        total_risk = sum(v.get_severity() for v in self.findings)
        
        critical = sum(1 for v in self.findings if v.get_severity() >= 90)
        high = sum(1 for v in self.findings if 70 <= v.get_severity() < 90)
        medium = sum(1 for v in self.findings if 50 <= v.get_severity() < 70)
        low = sum(1 for v in self.findings if v.get_severity() < 50)
        
        report = f"""
RAPPORT DE SECURITE
===================

Vulnerabilites trouvees: {len(self.findings)}
Score de risque total: {total_risk}

Distribution:
  - Critiques (90+): {critical}
  - Hautes (70-89): {high}
  - Moyennes (50-69): {medium}
  - Basses (<50): {low}

Alertes envoyees: {self.alert_system.get_alert_count()}
"""
        logger.info("Rapport genere")
        return report
    
    def get_summary(self):
        return {
            'total': len(self.findings),
            'critical': sum(1 for v in self.findings if v.get_severity() >= 90),
            'high': sum(1 for v in self.findings if 70 <= v.get_severity() < 90),
            'medium': sum(1 for v in self.findings if 50 <= v.get_severity() < 70),
            'low': sum(1 for v in self.findings if v.get_severity() < 50)
        }
