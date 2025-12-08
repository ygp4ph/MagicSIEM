# Guide Présentation - mini-SIEM

## Démarrage Rapide

```bash
cd mini-siem
python3 tests/test_all.py    # Vérifier que tout marche
python3 main.py               # Lancer les démos
```

## Structure (5 minutes de présentation)

### 1. Introduction (1 min)
- Projet: mini-SIEM pour gérer les vulnérabilités
- Technologies: Python + Design Patterns
- Objectif: Scanner, alerter, rapporter

### 2. Architecture (1 min)
Montrer l'arborescence dans README.md:
- core/ : Scanner + AlertSystem
- strategies/ : FileScan + NetworkScan  
- vulnerabilities/ : Classes de base + Decorators
- Tout simple, 10 fichiers Python

### 3. Pattern Strategy (1 min)
```python
scanner.set_strategy(FileScan("./projet", [".py"]))
scanner.run_scan()

scanner.set_strategy(NetworkScan("192.168.1.1", "1-1000"))
scanner.run_scan()
```
Interface IScanStrategy permet de changer facilement le type de scan.

### 4. Patterns Observer + Decorator (1.5 min)
- Observer: AlertSystem reçoit les alertes automatiquement
- Decorator: CriticalContextDecorator augmente la sévérité (+20)

Démo live du decorator:
```python
vuln = BasicVulnerability("TEST", 60)
decorated = CriticalContextDecorator(vuln, "Production")
# Sévérité passe de 60 à 80
```

### 5. Démo + Logs (0.5 min)
Lancer `python3 main.py` - montrer:
- Le scan qui tourne
- Les alertes qui s'affichent
- Le rapport final
- Le fichier de log généré

## Questions Probables

**Q: Pourquoi Strategy?**
R: Pour pouvoir ajouter facilement d'autres types de scan (dépendances, containers, etc.) sans modifier le Scanner.

**Q: Comment Observer améliore le système?**
R: Le Scanner ne gère plus les alertes directement, c'est découplé. On peut ajouter d'autres observateurs (Slack, email, etc.).

**Q: Le Decorator?**
R: Permet d'ajouter du contexte (production, DMZ, etc.) qui modifie la sévérité sans toucher à la classe de base.

## Commandes Utiles

```bash
# Tests
python3 tests/test_all.py

# Démo complète
python3 main.py

# Voir les logs
ls -ltr scan_*.log
cat scan_*.log | grep "CRITICAL\|WARNING"
```

## Points Clés

- Code simple et lisible (débutant/intermédiaire)
- Logs dans des fichiers avec timestamp
- Pas d'emojis, pas de fioritures
- Architecture claire: 4 dossiers, 10 fichiers
- 3 patterns bien implémentés
- Tests qui passent

## Distribution Groupe (4 personnes)

- Personne 1: Intro + Archi (2 min)
- Personne 2: Strategy (1.5 min)  
- Personne 3: Observer + Decorator (1.5 min)
- Personne 4: Démo + Logs (1 min)
- Tous: Questions (variable)
