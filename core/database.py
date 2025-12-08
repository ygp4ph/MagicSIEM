class VulnerabilityDB:
    DATA = {
        # CRITIQUES (90+)
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
        'eval(': {
            'id': 'CVE-2023-500', 'sev': 100, 'desc': 'Fonction dangereuse eval()',
            'detail': 'La fonction eval() exécute le texte passé en argument comme du code.',
            'sol': 'Remplacer eval() par des fonctions sûres.'
        },
        # HAUTES (70-89) - Ces bases deviennent CRITIQUES avec le décorateur (+20)
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
        # MOYENNES (50-69) - Ces bases deviennent HAUTES avec le décorateur (+20)
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
        # BASSES (<50)
        'TODO': {
            'id': 'WARN-001', 'sev': 30, 'desc': 'Dette Technique (TODO)',
            'detail': 'Code non terminé marqué par un TODO.',
            'sol': 'Planifier une revue de code pour traiter ces points.'
        }
    }

    @staticmethod
    def get_vuln(pattern):
        # ... (le reste de la fonction reste inchangé) ...
        return VulnerabilityDB.DATA.get(pattern, {
            'id': 'UNKNOWN', 
            'sev': 50, 
            'desc': 'Code suspect non identifié',
            'detail': f'Le pattern "{pattern}" est étrange.',
            'sol': 'Vérifier manuellement.'
        })