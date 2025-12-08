import os

def create_dummy_data():
    dir_name = "test_data"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
        print(f"Dossier '{dir_name}' créé.")

    # Fichier 1 : Contient des secrets (Critical)
    with open(f"{dir_name}/config_vuln.py", "w") as f:
        f.write("# Config file\n")
        f.write("db_password = 'admin123'  # FAIL: Hardcoded password\n")
        f.write("api_key = 'abcdef123456'  # FAIL: API Key exposed\n")
    
    # Fichier 2 : Contient du code dangereux (Critical)
    with open(f"{dir_name}/rce_vuln.py", "w") as f:
        f.write("import os\n")
        f.write("user_input = 'ls'\n")
        f.write("eval(user_input)  # FAIL: Eval is dangerous\n")

    # Fichier 3 : Dette technique (Low)
    with open(f"{dir_name}/notes.txt", "w") as f:
        f.write("TODO: Refactor this function later\n")
        f.write("TODO: Update documentation\n")

    print("Fichiers de test générés avec succès.")

if __name__ == "__main__":
    create_dummy_data()