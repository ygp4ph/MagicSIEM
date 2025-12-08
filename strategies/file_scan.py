import os
from strategies.scan_strategy import IScanStrategy
from vulnerabilities.vulnerability import BasicVulnerability
from core.database import VulnerabilityDB

class FileScan(IScanStrategy):
    
    def __init__(self, root_dir, extensions):
        self.root_dir = root_dir
        self.extensions = extensions
    
    def scan(self):
        findings = []
        patterns = ['password', 'api_key', 'eval(', 'sqli', 'xss', 'http', 'debug', 'TODO']
        
        if not os.path.exists(self.root_dir):
            return []

        for root, dirs, files in os.walk(self.root_dir):
            for filename in files:
                if any(filename.endswith(ext) for ext in self.extensions):
                    path = os.path.join(root, filename)
                    try:
                        with open(path, 'r', errors='ignore') as f:
                            for i, line in enumerate(f, 1):
                                for pat in patterns:
                                    if pat in line:
                                        info = VulnerabilityDB.get_vuln(pat)
                                        
                                        # --- MODIFICATION ICI ---
                                        # Format: <faille> trouvé dans <fichier> à la ligne <ligne>
                                        titre_formate = f"{info['desc']} trouvé dans {filename} à la ligne {i}"
                                        
                                        vuln = BasicVulnerability(
                                            titre_formate,
                                            info['sev'],
                                            detail=info['detail'],
                                            solution=info['sol']
                                        )
                                        findings.append(vuln)
                    except:
                        pass
        return findings