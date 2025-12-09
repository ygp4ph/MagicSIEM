class VulnerabilityDB:
    DATA = {
        # --- CRITIQUES (90+) ---
        'password': {
            'id': 'CVE-2024-001', 'sev': 95, 'desc': 'Mot de passe en clair',
            'detail': 'Un mot de passe est écrit en dur dans le code source.',
            'sol': 'Utiliser des variables d\'environnement ou un gestionnaire de secrets.'
        },
        'api_key': {
            'id': 'CVE-2024-002', 'sev': 90, 'desc': 'Clé API exposée',
            'detail': 'Une clé d\'accès à un service tiers est visible.',
            'sol': 'Révoquer la clé et la stocker de manière sécurisée (Vault, KMS).'
        },
        'exec(': {
            'id': 'CVE-2023-501', 'sev': 100, 'desc': 'Fonction dangereuse exec()',
            'detail': 'La fonction exec() exécute le texte passé en argument comme du code.',
            'sol': 'Remplacer exec() ou eval() par des fonctions sûres.'
        },
        'eval(': {
            'id': 'CVE-2023-500', 'sev': 100, 'desc': 'Fonction dangereuse eval()',
            'detail': 'La fonction eval() exécute le texte passé en argument comme du code.',
            'sol': 'Remplacer eval() par des fonctions sûres.'
        },
        
        # --- HAUTES (70-89) ---
        'sqli': {
            'id': 'CWE-89', 'sev': 85, 'desc': 'Injection SQL potentielle',
            'detail': 'Le code utilise une chaîne formatée pour une requête SQL sans paramétrisation.',
            'sol': 'Utiliser des requêtes paramétrées (Prepared Statements).'
        },
        'xss': {
            'id': 'CWE-79', 'sev': 75, 'desc': 'Vulnérabilité XSS potentielle',
            'detail': 'L\'affichage de données utilisateur non échappées (raw data) est dangereux.',
            'sol': 'Échapper (sanitize) toutes les sorties HTML provenant de l\'utilisateur.'
        },
        
        # PHP Spécifique
        'shell_exec(': {
            'id': 'PHP-01', 'sev': 80, 'desc': 'Exécution de commande PHP',
            'detail': 'Utilisation de shell_exec() ou system() pour exécuter des commandes système.',
            'sol': 'Éviter les appels shell; utiliser des fonctions natives PHP sûres.'
        },
        
        # Python Spécifique
        'subprocess.call(': {
            'id': 'PY-01', 'sev': 70, 'desc': 'Appel Shell non sécurisé Python',
            'detail': 'Exécution de commande via subprocess.call() avec shell=True.',
            'sol': 'Utiliser subprocess.run() sans shell=True et passer les arguments en liste.'
        },
        
        # --- MOYENNES (50-69) ---
        'console.log(': {
            'id': 'JS-01', 'sev': 50, 'desc': 'Information divulguée (Console)',
            'detail': 'Utilisation de console.log en production, pouvant exposer des données aux utilisateurs.',
            'sol': 'Supprimer console.log() avant la mise en production.'
        },
        'debug': {
            'id': 'WARN-002', 'sev': 60, 'desc': 'Mode Debug Actif',
            'detail': 'Le mode debug est activé en production, révélant des informations.',
            'sol': 'Passer DEBUG=False en production et utiliser des logs.'
        },
        'http': {
            'id': 'WARN-003', 'sev': 55, 'desc': 'Communication Non Sécurisée (HTTP)',
            'detail': 'Le code utilise des schémas HTTP au lieu de HTTPS pour des connexions externes.',
            'sol': 'Forcer l\'utilisation de HTTPS (chiffrement SSL/TLS).'
        },
        
        # --- BASSES (<50) ---
        'FIXME': {
            'id': 'WARN-004', 'sev': 45, 'desc': 'Dette Technique (FIXME)',
            'detail': 'Code marqué par un FIXME, indiquant un correctif rapide nécessaire.',
            'sol': 'Planifier le correctif et retirer la balise.'
        },
        'TODO': {
            'id': 'WARN-001', 'sev': 30, 'desc': 'Dette Technique (TODO)',
            'detail': 'Code non terminé marqué par un TODO.',
            'sol': 'Planifier une revue de code pour traiter ces points.'
        }
    }

    @staticmethod
    def get_vuln(pattern):
        return VulnerabilityDB.DATA.get(pattern, {
            'id': 'UNKNOWN', 
            'sev': 50, 
            'desc': 'Code suspect non identifié',
            'detail': f'Le pattern "{pattern}" est étrange.',
            'sol': 'Vérifier manuellement.'
        })