# main.py
from core.scanner import Scanner
from strategies.file import FileScan

if __name__ == "__main__":
    scanner = Scanner()
    target_folder = "./test_project"
    extensions_to_watch = [".py", ".txt", ".conf"]

    print(f">>> Configuration du Scanner sur le dossier '{target_folder}'")
    
    file_strategy = FileScan(target_folder, extensions_to_watch)
    scanner.set_strategy(file_strategy)
    scanner.run_scan()
    
    print(scanner.generate_report())