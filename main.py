import logging
import os
import time
import threading
from flask import Flask, render_template, jsonify, make_response, request
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor
from core.scanner import Scanner
from strategies.file_scan import FileScan
from core.vulnerability import BasicVulnerability

SCAN_CONFIG = {
    "directory": "/home/ygp4ph/Projets/MagicSIEM/test_data",
    "interval": 60,            # Intervalle de veille (1 minute)
    "monitoring_active": False # État du mode veille
}

SCAN_STATUS = "idle"  # États possibles: 'idle', 'running', 'error'
SCANNER = Scanner()   # Instance unique du scanner

# Exécuteur pour le scan manuel (1 seul à la fois)
executor = ThreadPoolExecutor(max_workers=1)

app = Flask(__name__)

# --- TÂCHE DE FOND : MODE VEILLE (MONITORING) ---
def monitoring_task():
    """Thread qui tourne en permanence pour la surveillance."""
    while True:
        target_dir = SCAN_CONFIG["directory"]
        is_active = SCAN_CONFIG["monitoring_active"]
        
        # On ne fait rien si le monitoring est désactivé
        if is_active:
            # Vérifications préliminaires
            if not target_dir:
                print("--- [VEILLE] En attente de configuration du dossier ---")
            
            # Si un scan MANUEL est déjà en cours, on saute ce tour pour ne pas faire conflit
            elif SCAN_STATUS == "running":
                print("--- [VEILLE] Scan manuel en cours, report de la veille ---")
            
            else:
                print(f"--- [VEILLE] Lancement analyse automatique sur {target_dir} ---")
                
                # Vérification de l'existence du dossier
                if not os.path.exists(target_dir):
                    SCANNER.reset()
                    sys_alert = BasicVulnerability(
                        f"ERREUR CRITIQUE: Dossier {target_dir} introuvable", 
                        100,
                        detail="Le dossier surveillé a disparu du système de fichiers.",
                        solution="Vérifiez le chemin saisi ou les permissions du dossier."
                    )
                    SCANNER.findings.append(sys_alert)
                    # Note: On ne change pas SCAN_STATUS pour ne pas bloquer l'interface
                else:
                    # Exécution du scan silencieux
                    SCANNER.reset()
                    SCANNER.set_strategy(FileScan(target_dir, [".py", ".txt", ".md", ".js", ".php"]))
                    SCANNER.run_scan()
                    print(f"--- [VEILLE] Analyse terminée ({len(SCANNER.findings)} résultats) ---")

        time.sleep(SCAN_CONFIG["interval"])

# Démarrage du thread de veille (Daemon = s'arrête quand le programme quitte)
monitor_thread = threading.Thread(target=monitoring_task, daemon=True)
monitor_thread.start()


# --- TÂCHE : SCAN MANUEL (ASYNC) ---

def execute_manual_scan(target_dir):
    global SCAN_STATUS
    try:
        # Validation stricte : on vérifie juste si le dossier existe
        if not os.path.exists(target_dir):
            SCANNER.reset()
            sys_alert = BasicVulnerability(
                f"ERREUR CRITIQUE: Dossier introuvable", 
                100, 
                detail=f"Chemin {target_dir} inaccessible ou inexistant.", 
                solution="Vérifiez le chemin absolu saisi."
            )
            SCANNER.findings.append(sys_alert)
            SCAN_STATUS = "error"
            return
            
        # Préparation du scan fichier uniquement
        SCANNER.reset()
        SCANNER.set_strategy(FileScan(target_dir, [".py", ".txt", ".md", ".js", ".php"]))
        
        print(f"--- [MANUEL] Scan fichier démarré sur {target_dir} ---")
        SCANNER.run_scan()
        SCAN_STATUS = "idle"

    except Exception as e:
        SCAN_STATUS = "error"
        logging.error(f"Erreur scan manuel: {e}")
# --- ROUTES FLASK ---

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/api/config/dir', methods=['POST'])
def set_directory():
    raw_path = request.json.get('path')
    if raw_path:
        # On force un chemin absolu pour la sécurité/clarté
        if not os.path.isabs(raw_path):
            return jsonify({"status": "error", "message": "Chemin absolu requis (commençant par / ou C:\\)"}), 400
            
        SCAN_CONFIG["directory"] = raw_path
        return jsonify({"status": "ok", "path": raw_path})
    return jsonify({"status": "error", "message": "Chemin vide"}), 400

@app.route('/api/scan', methods=['POST'])
def launch_scan():
    global SCAN_STATUS
    target_dir = SCAN_CONFIG["directory"]
    
    if not target_dir:
        return jsonify({"status": "error", "message": "Aucun dossier configuré."}), 400
    
    if SCAN_STATUS == "running":
        return jsonify({"status": "warning", "message": "Scan déjà en cours."}), 200

    SCAN_STATUS = "running"
    executor.submit(execute_manual_scan, target_dir)
    return jsonify({"status": "running", "message": "Scan lancé."})

@app.route('/api/toggle_monitoring', methods=['POST'])
def toggle_monitoring():
    # Inverse l'état du monitoring
    SCAN_CONFIG["monitoring_active"] = not SCAN_CONFIG["monitoring_active"]
    state = "activée" if SCAN_CONFIG["monitoring_active"] else "désactivée"
    return jsonify({
        "status": "ok", 
        "active": SCAN_CONFIG["monitoring_active"],
        "message": f"Veille {state}"
    })

@app.route('/api/status')
def get_status():
    return jsonify({"config": SCAN_CONFIG, "status": SCAN_STATUS})

@app.route('/api/data')
def get_data():
    stats = SCANNER.get_stats()
    logs = []
    for v in SCANNER.findings:
        detail = getattr(v, 'detail', 'Pas de détail disponible')
        sol = getattr(v, 'solution', 'Pas de solution disponible')
        logs.append({
            "title": v.get_title(), 
            "sev": v.get_severity(),
            "detail": detail,
            "sol": sol
        })
    return jsonify({"stats": stats, "logs": logs[-50:]})

R_CRITIQUE, G_CRITIQUE, B_CRITIQUE = 255, 71, 87     # Rouge
R_HAUTE, G_HAUTE, B_HAUTE = 255, 165, 2             # Orange
R_INFO, G_INFO, B_INFO = 186, 227, 100               # Vert Clair (Accent)

@app.route('/download/pdf')
def download_pdf():
    pdf = FPDF()
    pdf.add_page()
    
    # TITRE PRINCIPAL
    pdf.set_font("Arial", 'BU', size=16)
    pdf.cell(0, 15, txt="RAPPORT D'ANALYSE MAGICSIEM", ln=1, align='C')
    pdf.ln(5)
    
    stats = SCANNER.get_stats()
    target = SCAN_CONFIG['directory'] if SCAN_CONFIG['directory'] else "Non défini"
    
    # SECTION STATS
    pdf.set_fill_color(220, 220, 220)
    pdf.set_font("Arial", 'B', size=10)
    pdf.cell(0, 7, txt=f"Cible analysée : {target}", ln=1)
    pdf.cell(0, 7, txt=f"Total Vulnérabilités trouvées : {stats['count']}", ln=1)
    pdf.ln(10)
    
    # TITRE DE LA SECTION VULNÉRABILITÉS
    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt="DÉTAILS DES VULNÉRABILITÉS :", ln=1, align='L')
    
    # BOUCLE SUR LES VULNÉRABILITÉS
    for i, v in enumerate(SCANNER.findings, 1):
        
        score = v.get_severity()
        
        # Détermination des couleurs et du préfixe
        if score >= 90:
            prefix = "CRITIQUE"
            pdf.set_fill_color(R_CRITIQUE, G_CRITIQUE, B_CRITIQUE)
            pdf.set_text_color(255, 255, 255) # Texte blanc
        elif score >= 70:
            prefix = "HAUTE"
            pdf.set_fill_color(R_HAUTE, G_HAUTE, B_HAUTE)
            pdf.set_text_color(0, 0, 0) # Texte noir
        else:
            prefix = "INFORMATION / AUTRE"
            pdf.set_fill_color(R_INFO, G_INFO, B_INFO)
            pdf.set_text_color(0, 0, 0) # Texte noir

        # Bannière colorée (titre et sévérité)
        pdf.set_font("Arial", 'B', size=10)
        # 0.5 est l'épaisseur de la ligne
        pdf.cell(0, 6, txt=f" {i}. {v.get_title()} | Score: {score}", ln=1, fill=True) 
        
        # Réinitialisation du style du texte pour les détails
        pdf.set_text_color(0, 0, 0) # Texte noir
        pdf.set_font("Arial", size=9)
        pdf.ln(1)

        # 1. PROBLÈME (DÉTAIL)
        pdf.set_font("Arial", 'B', size=9)
        pdf.cell(0, 5, txt="PROBLÈME DÉTECTÉ :", ln=1)
        pdf.set_font("Arial", size=9)
        pdf.multi_cell(0, 4, txt=f"{getattr(v, 'detail', 'Détail non fourni.')}")
        
        # 2. SOLUTION
        pdf.ln(2)
        pdf.set_font("Arial", 'B', size=9)
        pdf.cell(0, 5, txt="SOLUTION / REMÉDIATION :", ln=1)
        pdf.set_font("Arial", size=9)
        pdf.multi_cell(0, 4, txt=f"{getattr(v, 'solution', 'Solution non fournie.')}")
        
        pdf.ln(5) # Espace avant la vulnérabilité suivante
        
    # ENVOI DE LA RÉPONSE
    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=rapport_siem.pdf'
    return response

if __name__ == "__main__":
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    print(">>> MagicSIEM démarré sur http://127.0.0.1:5000")
    app.run(debug=False, use_reloader=False)