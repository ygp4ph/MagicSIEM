import os

def create_dummy_data():
    dir_name = "test_data"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
        print(f"Dossier '{dir_name}' créé.")

    # Fichier 1 : Failles Critiques / Hautes
    with open(f"{dir_name}/config_critical.py", "w") as f:
        f.write("DB_USER_PASS = 'hardcoded_password_123'\n")  # password -> CRITIQUE
        f.write("G_API = 'mysecretapikey'\n")                  # api_key -> CRITIQUE
        f.write("user_input = input()\n")
        f.write("exec(user_input)\n")                          # eval / exec -> CRITIQUE

    # Fichier 2 : Failles Cyber Spécifiques
    with open(f"{dir_name}/web_app_vuln.py", "w") as f:
        f.write("query = 'SELECT * FROM users WHERE id = ' + user_id_raw\n") # sqli -> CRITIQUE (+20)
        f.write("html_output = '<div>' + user_comment\n")                     # xss -> CRITIQUE (+20)
        f.write("url = 'http://insecure.com/api'\n")                          # http -> HAUTE (+20)
        f.write("if debug == True: print('debug mode is on')\n")              # debug -> HAUTE (+20)
    
    # Fichier 3 : Dette technique
    with open(f"{dir_name}/notes.txt", "w") as f:
        f.write("TODO: Refactor this function later\n") # TODO -> MOYENNE (+20)

    print("Nouveaux fichiers de test générés.")

if __name__ == "__main__":
    create_dummy_data()