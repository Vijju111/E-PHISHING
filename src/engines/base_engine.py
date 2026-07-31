from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseEngine(ABC):
    """
    Abstract Base Class for all Enterprise Detection Engines.
    Each engine exposes an analyze method returning an EngineResult dictionary.
    """
    
    @abstractmethod
    def analyze(self, email_context: Dict[str, Any]) -> Dict[str, Any]:
        pass
