import logging
from datetime import datetime
from core.scanner import Scanner
from strategies.file_scan import FileScan
from strategies.network_scan import NetworkScan

def setup_logging():
    log_filename = f'scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_filename),
            logging.StreamHandler()
        ]
    )
    return log_filename

def demo_file_scan():
    print("\n--- DEMONSTRATION SCAN FICHIERS ---")
    
    scanner = Scanner()
    scanner.alert_system.configure("admin@example.com")
    
    file_strategy = FileScan("./test_data", [".py"])
    scanner.set_strategy(file_strategy)
    
    scanner.add_critical_context("Serveur Production")
    
    scanner.run_scan()
    
    print("\nRapport:")
    print(scanner.generate_report())

def demo_network_scan():
    print("\n--- DEMONSTRATION SCAN RESEAU ---")
    
    scanner = Scanner()
    
    network_strategy = NetworkScan("192.168.1.100", "1-5000")
    scanner.set_strategy(network_strategy)
    
    scanner.run_scan()
    
    print("\nRapport:")
    print(scanner.generate_report())

def demo_patterns():
    print("\n--- DEMONSTRATION DES PATTERNS ---")
    
    from vulnerabilities.vulnerability import BasicVulnerability
    from vulnerabilities.decorators import CriticalContextDecorator
    
    vuln = BasicVulnerability("TEST-001", 60)
    print(f"Vulnerabilite de base: {vuln.get_title()} - severite: {vuln.get_severity()}")
    
    decorated = CriticalContextDecorator(vuln, "Zone DMZ")
    print(f"Avec decorateur: {decorated.get_title()} - severite: {decorated.get_severity()}")

if __name__ == "__main__":
    log_file = setup_logging()
    print(f"Logs enregistres dans: {log_file}")
    
    demo_file_scan()
    
    input("\nAppuyez sur Entree pour continuer...")
    
    demo_network_scan()
    
    input("\nAppuyez sur Entree pour continuer...")
    
    demo_patterns()
    
    print("\n--- FIN DES DEMONSTRATIONS ---")
