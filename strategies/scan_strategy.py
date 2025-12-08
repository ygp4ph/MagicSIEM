from abc import ABC, abstractmethod

class IScanStrategy(ABC):
    
    @abstractmethod
    def scan(self):
        pass
