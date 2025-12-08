import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scanner import Scanner
from strategies.file_scan import FileScan
from vulnerabilities.vulnerability import BasicVulnerability
from vulnerabilities.decorators import CriticalContextDecorator

def test_vulnerability():
    print("Test 1: Vulnerability de base")
    vuln = BasicVulnerability("TEST-001", 75)
    assert vuln.get_severity() == 75
    assert "TEST-001" in vuln.get_title()
    print("  OK")

def test_decorator():
    print("Test 2: Decorator Pattern")
    vuln = BasicVulnerability("TEST-002", 60)
    decorated = CriticalContextDecorator(vuln, "Production")
    assert decorated.get_severity() == 80
    assert "CRITIQUE" in decorated.get_title()
    print("  OK")

def test_strategy():
    print("Test 3: Strategy Pattern")
    scanner = Scanner()
    strategy = FileScan("./test_data", [".py"])
    scanner.set_strategy(strategy)
    assert scanner.strategy is not None
    print("  OK")

def test_scanner():
    print("Test 4: Scanner Integration")
    scanner = Scanner()
    scanner.set_strategy(FileScan("./test_data", [".py"]))
    scanner.run_scan()
    assert len(scanner.findings) > 0
    print("  OK")

if __name__ == "__main__":
    print("\n=== TESTS UNITAIRES ===\n")
    
    try:
        test_vulnerability()
        test_decorator()
        test_strategy()
        test_scanner()
        
        print("\n=== TOUS LES TESTS PASSES ===\n")
    except AssertionError as e:
        print(f"\nERREUR: {e}")
        sys.exit(1)
