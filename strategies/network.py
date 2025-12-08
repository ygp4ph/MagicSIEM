from typing import List
from .base import IScanStrategy
from vulnerabilities.base import Vulnerability
from vulnerabilities.impl import BasicVulnerability

class NetworkScan(IScanStrategy):
    def __init__(self, target_ip: str, port_range: str):
        self.target_ip = target_ip
        self.port_range = port_range

    def scan(self) -> List[Vulnerability]:
        print(f"--- Scanning Network {self.target_ip} ---")
        return [BasicVulnerability("CVE-NET-01", 50)]