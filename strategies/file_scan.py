import os
from strategies.scan_strategy import IScanStrategy
from core.vulnerability import BasicVulnerability
from core.database import VulnerabilityDB

class FileScan(IScanStrategy):
    
    def __init__(self, root_dir, extensions):
        self.root_dir = root_dir
        self.extensions = extensions
    
    def scan(self):
        findings = []
        # --- LISTE FINALE DES 13 PATTERNS ---
        patterns = [
            'password', 'api_key',           # Secrets (2)
            'eval(', 'exec(', 'subprocess.call(', 'shell_exec(', # Exécution de commandes (4)
            'sqli', 'xss',                   # Vulnérabilités Web (2)
            'http', 'debug', 'console.log(', # Configurations/Fuites (3)
            'TODO', 'FIXME'                  # Dette Technique (2)
        ]
        
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
                                    # Si le pattern est trouvé dans la ligne
                                    if pat in line:
                                        info = VulnerabilityDB.get_vuln(pat)
                                        
                                        # Format: <description> trouvé dans <fichier> à la ligne <ligne>
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