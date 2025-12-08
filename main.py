import threading
import time
import logging
import os
from flask import Flask, render_template, jsonify, make_response, request
from fpdf import FPDF

from core.scanner import Scanner
from strategies.file_scan import FileScan
from vulnerabilities.vulnerability import BasicVulnerability

# --- CONFIGURATION GLOBALE ---
SCAN_CONFIG = {
    "directory": "./test_data",  # Repertoire par defaut
    "active": True,              # Scan perpetuel actif ou non
    "interval": 60               # Pause entre les scans (secondes)
}

app = Flask(__name__)
scanner = Scanner()

# --- Thread de Veille (Pilotable) ---
def monitoring_task():
    while True:
        if SCAN_CONFIG["active"]:
            target_dir = SCAN_CONFIG["directory"]
            print(f"--- [VEILLE] Scan de {target_dir} ---")
            
            # Mise a jour de la strategie avec le repertoire courant
            scanner.set_strategy(FileScan(target_dir, [".py", ".txt", ".md", ".js", ".php"]))
            
            if not os.path.exists(target_dir):
                scanner.reset()
                sys_alert = BasicVulnerability(
                    f"ERREUR: Dossier {target_dir} introuvable", 
                    100,
                    detail="Le dossier surveillé n'existe pas ou n'est pas accessible.",
                    solution="Vérifiez le chemin dans la configuration."
                )
                scanner.findings.append(sys_alert)
                scanner.alert_system.send_alert(sys_alert)
            else:
                scanner.reset()
                scanner.add_critical_context("Production") 
                scanner.run_scan()
        else:
            print("--- [VEILLE] En pause ---")
            
        time.sleep(SCAN_CONFIG["interval"])

monitor_thread = threading.Thread(target=monitoring_task, daemon=True)
monitor_thread.start()

# --- Routes Web ---

@app.route('/')
def dashboard():
    return render_template('index.html')

# API pour recuperer l'etat du scanner (pour l'affichage)
@app.route('/api/status')
def get_status():
    return jsonify(SCAN_CONFIG)

# API pour changer le repertoire
@app.route('/api/config/dir', methods=['POST'])
def set_directory():
    raw_path = request.json.get('path')
    
    if raw_path:
        # VERIFICATION STRICTE : Le chemin doit être déjà absolu
        if not os.path.isabs(raw_path):
            return jsonify({
                "status": "error", 
                "message": "Erreur : Vous devez saisir un chemin absolu (commençant par /)"
            }), 400
            
        SCAN_CONFIG["directory"] = raw_path
        return jsonify({"status": "ok", "path": raw_path})
        
    return jsonify({"status": "error"}), 400
# API pour Start/Stop
@app.route('/api/config/toggle', methods=['POST'])
def toggle_scan():
    SCAN_CONFIG["active"] = not SCAN_CONFIG["active"]
    return jsonify({"status": "ok", "active": SCAN_CONFIG["active"]})

@app.route('/api/data')
def get_data():
    stats = scanner.get_stats()
    logs = []
    for v in scanner.findings:
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
    pdf.cell(200, 10, txt="Rapport de Securite - Mini SIEM", ln=1, align='C')
    pdf.ln(10)
    stats = scanner.get_stats()
    pdf.cell(200, 10, txt=f"Cibles: {SCAN_CONFIG['directory']}", ln=1)
    pdf.cell(200, 10, txt=f"Total Vulnerabilites: {stats['count']}", ln=1)
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    for v in scanner.findings:
        col = "CRITIQUE" if v.get_severity() >= 90 else "INFO"
        pdf.cell(0, 10, txt=f"[{col}] {v.get_title()}", ln=1)
    response = make_response(pdf.output(dest='S').encode('latin-1'))
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = 'attachment; filename=rapport_siem.pdf'
    return response

if __name__ == "__main__":
    logging.getLogger('werkzeug').setLevel(logging.ERROR)
    print("Dashboard accessible sur http://127.0.0.1:5000")
    app.run(debug=False, use_reloader=False)