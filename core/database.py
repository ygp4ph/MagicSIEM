class VulnerabilityDB:
    DATA = {
        'password': {
            'id': 'CVE-2024-001', 
            'sev': 95, 
            'desc': 'Mot de passe en clair',  # Simplifié (c'est le <faille>)
            'detail': 'Un mot de passe est écrit en dur dans le code.',
            'sol': 'Utiliser des variables d\'environnement.'
        },
        'api_key': {
            'id': 'CVE-2024-002', 
            'sev': 90, 
            'desc': 'Clé API exposée',
            'detail': 'Une clé d\'accès service tiers est visible.',
            'sol': 'Révoquer et utiliser un fichier .env.'
        },
        'eval(': {
            'id': 'CVE-2023-500', 
            'sev': 100, 
            'desc': 'Fonction dangereuse eval()',
            'detail': 'Exécution de code arbitraire possible via eval().',
            'sol': 'Utiliser ast.literal_eval() à la place.'
        },
        'TODO': {
            'id': 'WARN-001', 
            'sev': 30, 
            'desc': 'Dette Technique (TODO)',
            'detail': 'Code non terminé marqué par un TODO.',
            'sol': 'Prévoir une revue de code.'
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