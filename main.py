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
    "directory": "/home/ygp4ph/Projets/mini-SIEM/test_data",
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

@app.route('/download/pdf')
def download_pdf():
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport de Securite - MagicSIEM", ln=1, align='C')
    pdf.ln(10)
    
    stats = SCANNER.get_stats()
    target = SCAN_CONFIG['directory'] if SCAN_CONFIG['directory'] else "Non défini"
    
    pdf.set_font("Arial", 'B', size=10)
    pdf.cell(200, 10, txt=f"Cible : {target}", ln=1)
    pdf.cell(200, 10, txt=f"Total Vulnérabilités : {stats['count']}", ln=1)
    pdf.ln(5)
    
    pdf.set_font("Arial", size=9)
    for v in SCANNER.findings:
        prefix = "[CRITIQUE]" if v.get_severity() >= 90 else "[INFO]"
        pdf.cell(0, 8, txt=f"{prefix} {v.get_title()} (Score: {v.get_severity()})", ln=1)
        
    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=rapport_siem.pdf'
    return response

if __name__ == "__main__":
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    print(">>> MagicSIEM démarré sur http://127.0.0.1:5000")
    app.run(debug=False, use_reloader=False)