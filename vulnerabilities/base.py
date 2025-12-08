from abc import ABC, abstractmethod

class Vulnerability(ABC):
    @abstractmethod
    def get_severity(self) -> int: pass
    
    @abstractmethod
    def get_title(self) -> str: pass
    
    @abstractmethod
    def get_remediation(self) -> str: pass