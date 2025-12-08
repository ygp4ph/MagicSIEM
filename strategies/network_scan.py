import logging
from strategies.scan_strategy import IScanStrategy
from vulnerabilities.vulnerability import BasicVulnerability

logger = logging.getLogger(__name__)

class NetworkScan(IScanStrategy):
    
    def __init__(self, target_ip, port_range):
        self.target_ip = target_ip
        self.port_range = port_range
    
    def scan(self):
        logger.info(f"Debut scan reseau: {self.target_ip} ports {self.port_range}")
        findings = []
        
        ports_vuln = {
            21: ('FTP-WEAK', 70),
            23: ('TELNET', 85),
            3389: ('RDP-EXPOSE', 75),
            445: ('SMB-VULN', 90)
        }
        
        start, end = map(int, self.port_range.split('-'))
        
        for port, (cve, score) in ports_vuln.items():
            if start <= port <= end:
                vuln = BasicVulnerability(f"NET-{cve}", score)
                logger.warning(f"Port {port} vulnerable")
                findings.append(vuln)
        
        logger.info(f"Scan reseau termine: {len(findings)} vulnerabilites")
        return findings
