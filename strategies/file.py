import os
from typing import List
from .base import IScanStrategy
from vulnerabilities.base import Vulnerability
from vulnerabilities.impl import BasicVulnerability

class FileScan(IScanStrategy):
    def __init__(self, root_directory: str, file_extensions: List[str]):
        self.root_directory = root_directory
        self.file_extensions = file_extensions

    def scan(self) -> List[Vulnerability]:
        print(f"Démarrage de l'analyse statique dans : {self.root_directory} ---")
        findings = []

        for root, dirs, files in os.walk(self.root_directory):
            for filename in files:
                if any(filename.endswith(ext) for ext in self.file_extensions):
                    full_path = os.path.join(root, filename)
                    new_vulns = self._analyze_file(full_path, filename)
                    findings.extend(new_vulns)

        return findings

    def _analyze_file(self, filepath: str, filename: str) -> List[Vulnerability]:
        """Méthode privée pour analyser un fichier ligne par ligne"""
        file_vulns = []
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for i, line in enumerate(lines):
                    line_num = i + 1
                    content = line.strip()
                    if "password =" in content or "api_key =" in content:
                        v = BasicVulnerability(
                            cve_code=f"HARDCODED-SECRET",
                            base_score=80
                        )
                        print(f"   [!] Secret trouvé dans {filename} ligne {line_num}")
                        file_vulns.append(v)

                    elif "eval(" in content:
                        v = BasicVulnerability(
                            cve_code=f"DANGEROUS-CODE-EVAL",
                            base_score=90
                        )
                        print(f"   [!] Code dangereux (eval) dans {filename} ligne {line_num}")
                        file_vulns.append(v)

                    elif "TODO" in content or "FIXME" in content:
                        v = BasicVulnerability(
                            cve_code=f"INFO-TODO-COMMENT",
                            base_score=10
                        )
                        file_vulns.append(v)

        except Exception as e:
            print(f"Erreur lors de la lecture de {filename}: {e}")

        return file_vulns