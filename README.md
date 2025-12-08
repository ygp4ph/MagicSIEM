# mini-SIEM

Système de gestion de vulnérabilités - Projet POO Avancée

## Structure

```
mini-siem/
├── core/
│   ├── scanner.py          # Scanner principal
│   └── alert_system.py     # Système d'alertes (Observer)
├── strategies/
│   ├── scan_strategy.py    # Interface Strategy
│   ├── file_scan.py        # Scan de fichiers
│   └── network_scan.py     # Scan réseau
├── vulnerabilities/
│   ├── vulnerability.py    # Classe de base
│   └── decorators.py       # Pattern Decorator
├── tests/
│   └── test_all.py         # Tests unitaires
├── test_data/
│   └── app.py              # Fichier de test
└── main.py                 # Programme principal
```

## Installation

Aucune dépendance externe requise. Python 3.8+

```bash
cd mini-siem
python3 main.py
```

## Tests

```bash
python3 tests/test_all.py
```

## Patterns Implémentés

### Strategy Pattern
Permet de changer le type de scan dynamiquement:
- FileScan: Analyse de fichiers
- NetworkScan: Scan réseau

### Observer Pattern
AlertSystem observe et notifie les vulnérabilités détectées en temps réel.

### Decorator Pattern
CriticalContextDecorator enrichit les vulnérabilités avec un contexte critique qui augmente la sévérité.

## Utilisation

```python
from core.scanner import Scanner
from strategies.file_scan import FileScan

scanner = Scanner()
scanner.set_strategy(FileScan("./mon_projet", [".py"]))
scanner.run_scan()

print(scanner.generate_report())
```

## Logs

Les scans génèrent automatiquement un fichier de log avec timestamp.

## Fonctionnalités

- Détection de secrets en dur (passwords, API keys)
- Détection de code dangereux (eval, exec)
- Scan de ports réseau
- Système d'alertes par sévérité
- Rapports détaillés
- Logging complet
