import os
import logging
from strategies.scan_strategy import IScanStrategy
from vulnerabilities.vulnerability import BasicVulnerability

logger = logging.getLogger(__name__)

class FileScan(IScanStrategy):
    
    def __init__(self, root_dir, extensions):
        self.root_dir = root_dir
        self.extensions = extensions
    
    def scan(self):
        logger.info(f"Debut scan fichiers: {self.root_dir}")
        findings = []
        
        for root, dirs, files in os.walk(self.root_dir):
            for filename in files:
                if any(filename.endswith(ext) for ext in self.extensions):
                    filepath = os.path.join(root, filename)
                    findings.extend(self._analyser_fichier(filepath))
        
        logger.info(f"Scan termine: {len(findings)} vulnerabilites")
        return findings
    
    def _analyser_fichier(self, filepath):
        vulns = []
        patterns = {
            'password': 80,
            'api_key': 85,
            'eval(': 90,
            'exec(': 95
        }
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f, 1):
                    for pattern, score in patterns.items():
                        if pattern in line.lower():
                            vuln = BasicVulnerability(
                                f"FILE-{pattern.upper()}-L{i}",
                                score
                            )
                            logger.warning(f"{filepath}:{i} - {pattern}")
                            vulns.append(vuln)
        except Exception as e:
            logger.error(f"Erreur lecture {filepath}: {e}")
        
        return vulns
