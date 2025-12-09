import logging
from core.alert_system import AlertSystem

logger = logging.getLogger(__name__)

class Scanner:
    
    def __init__(self):
        self.strategy = None
        self.alert_system = AlertSystem()
        self.findings = []
        # self.critical_contexts a été supprimé
    
    def set_strategy(self, strategy):
        self.strategy = strategy
    
    # La méthode add_critical_context a été supprimée
            
    def reset(self):
        # Vide les resultats precedents pour eviter les doublons
        self.findings = []
    
    def run_scan(self):
        if not self.strategy:
            return
        
        raw_results = self.strategy.scan()
        
        for vuln in raw_results:
            final_vuln = vuln
            # Le Pattern Decorator n'est plus appliqué ici
            
            self.findings.append(final_vuln)
            # Pattern Observer: on notifie l'AlertSystem avec la vulnérabilité de base
            self.alert_system.send_alert(final_vuln)

    def get_stats(self):
        # (Cette fonction doit toujours être mise à jour avec la version incluant 'todo' si ce n'est pas déjà fait)
        # Assurez-vous d'avoir la version correcte dans votre fichier réel
        critical = sum(1 for v in self.findings if v.get_severity() >= 90)
        high = sum(1 for v in self.findings if 70 <= v.get_severity() < 90)
        medium = sum(1 for v in self.findings if 50 <= v.get_severity() < 70)
        # Ajoutez le calcul 'todo' ici si vous l'aviez
        technical_debt = sum(1 for v in self.findings if "Dette Technique" in v.get_title())

        return {
            'count': len(self.findings),
            'critical': critical,
            'high': high,
            'medium': medium,
            'todo': technical_debt
        }