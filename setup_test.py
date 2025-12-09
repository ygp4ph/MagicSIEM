import os
import subprocess # Ajout de l'import pour la ligne subprocess

def create_dummy_data():
    dir_name = "test_data"
    
    # Création du dossier s'il n'existe pas
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
        print(f"Dossier '{dir_name}' créé.")
    
    # --- 1. Fichiers CRITIQUES et SECRETS (password, api_key, exec() ) ---
    with open(f"{dir_name}/config_critical.py", "w") as f:
        f.write("# Configuration critique\n")
        f.write("DB_PASSWORD = 'hardcoded_password_123'  # DETECTION: password\n")
        f.write("AWS_SECRET = 'AKIA_TEST_KEY_12345'       # DETECTION: api_key\n")
        f.write("exec('print(\"critical\")')           # DETECTION: exec(\n")
        f.write("command = input('Enter command: ')\n")
        f.write("os.system(f'echo {command}')\n")


    # --- 2. Fichier WEB VULNÉRABLE (eval, XSS, subprocess.call) ---
    with open(f"{dir_name}/web_app_vuln.py", "w") as f:
        f.write("import os\n")
        f.write("# Vulnerabilités Web\n")
        f.write("user_cmd = input()\n")
        f.write("eval(user_cmd)                            # DETECTION: eval(\n")
        f.write("print('<div>' + user_input)               # DETECTION: xss\n")
        f.write("subprocess.call(['ls', '-l'], shell=True)  # DETECTION: subprocess.call(\n")

    
    # --- 3. Fichier LEGACY (sqli, http, debug) ---
    with open(f"{dir_name}/legacy_api.py", "w") as f:
        f.write("# Ancien module de connexion\n")
        f.write("def get_user(user_id):\n")
        f.write("    url = 'http://api.ancien-serveur.com' # DETECTION: http\n")
        f.write("    query = 'SELECT * FROM users WHERE id = ' + user_id # DETECTION: sqli\n")
        f.write("    DEBUG = True # DETECTION: debug\n")
        f.write("    print('Fetching data...')\n")

    # --- 4. Fichier PHP SPÉCIFIQUE (shell_exec, FIXME) ---
    with open(f"{dir_name}/php_legacy.php", "w") as f:
        f.write("<?php\n")
        f.write("// Module de test PHP\n")
        f.write("if (isset($_GET['cmd'])) {\n")
        f.write("    shell_exec($_GET['cmd']); // DETECTION: shell_exec(\n")
        f.write("}\n")
        f.write("// FIXME: Cette fonction est lente\n")


    # --- 5. Fichier JS SPÉCIFIQUE (console.log, http) ---
    with open(f"{dir_name}/front_end.js", "w") as f:
        f.write("// Fichier JavaScript\n")
        f.write("function logData(user) {\n")
        f.write("    console.log('User data:', user); // DETECTION: console.log(\n")
        f.write("}\n")
        f.write("var api_endpoint = 'http://insecure-api.dev'; // DETECTION: http\n")


    # --- 6. Dette technique (TODO, FIXME) ---
    with open(f"{dir_name}/notes.txt", "w") as f:
        f.write("TODO: Refactoriser la classe User\n")     # DETECTION: TODO
        f.write("TODO: Mettre à jour la doc\n")
        f.write("FIXME: La validation des entrées n'est pas complète.\n") # DETECTION: FIXME


    print("Fichiers de test générés avec succès pour une couverture complète.")

if __name__ == "__main__":
    create_dummy_data()