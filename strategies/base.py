from abc import ABC, abstractmethod
from typing import List
from vulnerabilities.base import Vulnerability

class IScanStrategy(ABC):
    @abstractmethod
    def scan(self) -> List[Vulnerability]:
        pass