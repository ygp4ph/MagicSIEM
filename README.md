# MagicSIEM

Un outil d'analyse statique de code pour détecter des vulnérabilités basiques.

MagicSIEM scanne des répertoires à la recherche de patterns suspects dans le code source (mots de passe en clair, fonctions dangereuses, etc.).

Le projet comprend :
- Un scanner de fichiers qui cherche des mots-clés dangereux
- Une interface web pour lancer les scans et voir les résultats
- Un mode surveillance qui tourne en arrière-plan
- L'export des résultats en PDF

## Ce que ça fait (et ce que ça ne fait pas)

**Ce que ça détecte :**
- Mots de passe en dur dans le code
- Clés API exposées
- Utilisation de fonctions dangereuses (eval, etc.)
- Requêtes SQL non paramétrées
- Potentiels XSS
- Connexions HTTP non sécurisées
- Mode debug activé
- TODO et dette technique

**Limitations :**
- C'est de l'analyse statique basique (un grep amélioré)
- Pas mal de faux positifs possibles

### 1. Strategy Pattern

Permet de choisir l'algorithme de scan à la volée. Pour l'instant, il n'y a que FileScan qui est vraiment implémenté.

```python
# Dans Scanner
scanner.set_strategy(FileScan(target_dir, extensions))
scanner.run_scan()
```

Structure :
- `IScanStrategy` : interface abstraite avec une méthode scan()
- `FileScan` : implémentation pour scanner des fichiers
- `NetworkScan` : structure vide pour plus tard

### 2. Observer Pattern

Le système d'alertes reçoit automatiquement une notification quand le scanner trouve quelque chose.

```python
# Dans Scanner.run_scan()
for vuln in raw_results:
    self.findings.append(vuln)
    self.alert_system.send_alert(vuln)  # Notif automatique
```

### 3. Decorator Pattern

Modifie la sévérité d'une vulnérabilité selon le contexte (Production, Public, etc.). Une XSS à 75 en dev devient 95 en prod.

```python
vuln = BasicVulnerability("XSS détecté", 75)
decorated = CriticalContextDecorator(vuln, "Production")
# Sévérité passe à 95 (75 + 20)
```

### Organisation générale

```
Flask (main.py)
    │
    └── Scanner (core/scanner.py)
            ├── Strategy (FileScan / NetworkScan)
            │       └── VulnerabilityDB
            │
            └── AlertSystem (Observer)
```

## Installation

```bash
# Cloner le projet
git clone https://github.com/ton-username/MagicSIEM.git
cd MagicSIEM

# Environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou venv\Scripts\activate sur Windows

# Dépendances
pip install -r requirements.txt
```

Si on veut tester rapidement :
```bash
python setup_test.py  # Génère des fichiers de test avec des vulnérabilités
```

## Utilisation

### Lancer l'application

```bash
python main.py
```

Ouvrir son navigateur sur `http://127.0.0.1:5000`

### Interface web

1. **Configurer le scan**
   - Entrer le chemin absolu du dossier à analyser (ex: `/home/user/mon_projet`)
   - Cliquer sur "Charger"

2. **Lancer un scan**
   - Cliquer sur "Analyser" pour un scan manuel
   - Ou activer le "Mode Veille" pour une surveillance continue (toutes les minutes)

3. **Voir les résultats**
   - Les stats s'affichent en temps réel
   - Cliquer sur une vulnérabilité pour voir les détails
   - Export PDF disponible après le scan

### Exemple de chemin valide
```
# Linux
/home/ygp4ph/Projets/projet_web

# Windows  
C:\Users\Shaadi\Documents\projet_web
```

Note : Le chemin doit être absolu (commençant par / ou C:\)

## Structure du projet

```
MagicSIEM/
│
├── main.py                    # Application Flask + routes API
├── requirements.txt           
├── setup_test.py             # Génère des fichiers de test
│
├── core/                     
│   ├── scanner.py            # Orchestration du scan
│   ├── alert_system.py       # Observer pattern
│   └── database.py           # Base des vulnérabilités connues
│
├── strategies/               
│   ├── scan_strategy.py      # Interface Strategy
│   ├── file_scan.py          # Scan de fichiers (implémenté)
│   └── network_scan.py       # Scan réseau (structure vide)
│
├── vulnerabilities/          
│   ├── vulnerability.py      # Classes de base
│   └── decorators.py         # Decorator pattern
│
└── templates/                
    └── index.html            # Dashboard web
```

## Vulnérabilités détectées

| Pattern | Sévérité de base | Description |
|---------|------------------|-------------|
| `eval(` | 100 | Fonction dangereuse |
| `password` | 95 | Mot de passe en clair |
| `api_key` | 90 | Clé API exposée |
| `sqli` | 85 | Injection SQL |
| `xss` | 75 | XSS potentiel |
| `debug` | 60 | Mode debug |
| `http` | 55 | HTTP non sécurisé |
| `TODO` | 30 | Dette technique |

Avec le contexte "Production", +20 points de sévérité.

---

sh44di, Advm100, nammsofresh, ygp4ph, Thai-Lung
