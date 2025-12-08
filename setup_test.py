import os

def create_dummy_data():
    dir_name = "test_data"
    
    # Création du dossier s'il n'existe pas
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
        print(f"✅ Dossier '{dir_name}' créé.")

    # 1. Fichier avec des secrets (CRITIQUE)
    with open(f"{dir_name}/config_critical.py", "w") as f:
        f.write("# Configuration critique\n")
        f.write("DB_PASSWORD = 'hardcoded_password_123'  # DETECTION: password\n")
        f.write("AWS_SECRET = 'AKIA_TEST_KEY_12345'       # DETECTION: api_key\n")
    
    # 2. Fichier web vulnérable (HAUTE / CRITIQUE)
    with open(f"{dir_name}/web_app_vuln.py", "w") as f:
        f.write("import os\n")
        f.write("# Vulnerabilités Web\n")
        f.write("user_cmd = input()\n")
        f.write("eval(user_cmd)                            # DETECTION: eval(\n")
        f.write("print('<div>' + user_input)               # DETECTION: xss\n")
    
    # 3. Dette technique (MOYENNE / AUTRE)
    with open(f"{dir_name}/notes.txt", "w") as f:
        f.write("TODO: Refactoriser la classe User\n")     # DETECTION: TODO
        f.write("TODO: Mettre à jour la doc\n")

    # --- NOUVEAU FICHIER AJOUTÉ ---
    # 4. Vieux connecteur API (Injection SQL + HTTP)
    with open(f"{dir_name}/legacy_api.py", "w") as f:
        f.write("# Ancien module de connexion\n")
        f.write("def get_user(user_id):\n")
        f.write("    # Connexion non sécurisée\n")
        f.write("    url = 'http://api.ancien-serveur.com' # DETECTION: http\n")
        f.write("    \n")
        f.write("    # Requête non paramétrée (Injection SQL)\n")
        f.write("    query = 'SELECT * FROM users WHERE id = ' + user_id # DETECTION: sqli\n")
        f.write("    print('Fetching data...')\n")

    print("✅ Fichiers de test générés avec succès (y compris legacy_api.py).")

if __name__ == "__main__":
    create_dummy_data()