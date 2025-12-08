import logging

logger = logging.getLogger(__name__)

class AlertSystem:
    
    def __init__(self):
        self.admin_email = ""
        self.alert_count = 0
    
    def configure(self, email):
        self.admin_email = email
        logger.info(f"Alertes configurees pour {email}")
    
    def send_alert(self, vuln):
        self.alert_count += 1
        severity = vuln.get_severity()
        
        if severity >= 90:
            level = "CRITIQUE"
        elif severity >= 70:
            level = "HAUTE"
        elif severity >= 50:
            level = "MOYENNE"
        else:
            level = "BASSE"
        
        logger.warning(f"Alerte [{level}]: {vuln.get_title()} (severite: {severity})")
        
        if severity >= 90:
            logger.critical(f"Email envoye a {self.admin_email}")
    
    def get_alert_count(self):
        return self.alert_count
