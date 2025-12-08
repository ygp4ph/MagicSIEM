import logging
import os
from flask import Flask, render_template, jsonify, make_response, request
from fpdf import FPDF
from concurrent.futures import ThreadPoolExecutor # Pour les scans asynchrones

from core.scanner import Scanner
from strategies.file_scan import FileScan
from vulnerabilities.vulnerability import BasicVulnerability

# --- CONFIGURATION GLOBALE ET STATUT ---
SCAN_CONFIG = {
    "directory": "",         # Vide par défaut
    "interval": 60           # Intervalle conservé mais inutilisé
}
SCAN_STATUS = "idle" # 'idle', 'running', 'error'
SCANNER = Scanner() # Scanner global

# Exécuteur pour lancer le scan en arrière-plan (max 1 scan a la fois)
executor = ThreadPoolExecutor(max_workers=1)

app = Flask(__name__)

# Ancienne fonction monitoring_task est SUPPRIMÉE

# Logique de scan exécutée par l'executor
def execute_scan(target_dir):
    global SCAN_STATUS
    try:
        # La validation du chemin absolu a ete faite par la route /api/config/dir
        
        if not os.path.exists(target_dir):
            # Enregistrement de l'erreur dans les findings pour affichage
            SCANNER.reset()
            sys_alert = BasicVulnerability(
                f"ERREUR CRITIQUE: Dossier {target_dir} introuvable", 
                100,
                detail="Le dossier surveillé n'existe pas ou n'est pas accessible. Vérifiez le chemin.",
                solution="Vérifiez le chemin saisi ou les permissions du dossier."
            )
            SCANNER.findings.append(sys_alert)
            SCAN_STATUS = "error"
            return "Dossier introuvable"

        # 1. Préparation du scan
        SCANNER.reset()
        SCANNER.set_strategy(FileScan(target_dir, [".py", ".txt", ".md", ".js", ".php"]))
        SCANNER.add_critical_context("Production") 
        
        # 2. Exécution
        print(f"--- [SCAN] Debut de l'analyse de {target_dir} ---")
        SCANNER.run_scan()
        
        # 3. Fin du scan
        print(f"--- [SCAN] Analyse terminee ---")
        SCAN_STATUS = "idle"
        return "Scan terminé"

    except Exception as e:
        SCAN_STATUS = "error"
        logging.error(f"Erreur lors de l'exécution du scan: {e}")
        return f"Erreur: {e}"


# --- Routes Web ---

@app.route('/')
def dashboard():
    return render_template('index.html')

# API pour lancer le scan
@app.route('/api/scan', methods=['POST'])
def launch_scan():
    global SCAN_STATUS
    target_dir = SCAN_CONFIG["directory"]
    
    # 1. Validation du chemin (Doit être absolu et non vide)
    if not target_dir or not os.path.isabs(target_dir):
        return jsonify({"status": "error", "message": "Veuillez d'abord saisir un chemin absolu valide."}), 400
    
    # 2. Vérification si un scan est déjà en cours
    if SCAN_STATUS == "running":
        return jsonify({"status": "warning", "message": "Un scan est déjà en cours."}), 200

    # 3. Lancement asynchrone du scan
    SCAN_STATUS = "running"
    executor.submit(execute_scan, target_dir)
    
    return jsonify({"status": "running", "message": "Scan lancé avec succès."})


# API pour changer le repertoire (strictement absolu)
@app.route('/api/config/dir', methods=['POST'])
def set_directory():
    raw_path = request.json.get('path')
    
    if raw_path:
        if not os.path.isabs(raw_path):
            return jsonify({
                "status": "error", 
                "message": "Erreur : Vous devez saisir un chemin absolu (commençant par /)"
            }), 400
            
        SCAN_CONFIG["directory"] = raw_path
        return jsonify({"status": "ok", "path": raw_path})
        
    return jsonify({"status": "error"}), 400

# API pour recuperer l'etat du scanner et la config
@app.route('/api/status')
def get_status():
    return jsonify({"config": SCAN_CONFIG, "status": SCAN_STATUS})


@app.route('/api/data')
def get_data():
    # Reste inchangé, utilise le SCANNER global
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


# La route de téléchargement PDF utilise également le SCANNER global
@app.route('/download/pdf')
def download_pdf():
    # ... (code de la route download/pdf inchangé) ...
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Rapport de Securite - Mini SIEM", ln=1, align='C')
    pdf.ln(10)
    
    stats = SCANNER.get_stats()
    pdf.cell(200, 10, txt=f"Cibles: {SCAN_CONFIG['directory']}", ln=1)
    pdf.cell(200, 10, txt=f"Total Vulnerabilites: {stats['count']}", ln=1)
    pdf.ln(10)
    pdf.set_font("Arial", size=10)
    for v in SCANNER.findings:
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