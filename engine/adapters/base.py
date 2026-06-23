from abc import ABC, abstractmethod
from typing import Dict, Any
from core.types import ExecutionContext

class BaseAdapter(ABC):
    """Legacy base class for engine adapters."""
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def execute(self, command_id: str, command: str, timeout: int = 5):
        pass

class BaseSandboxAdapter(ABC):
    """
    Formal interface for all UCSER sandbox adapters.
    Ensures consistent signatures for execution, cleanup, and state retrieval.
    """
    
    @abstractmethod
    def run(self, command: str, context: ExecutionContext) -> Dict[str, Any]:
        """
        Executes a command within the isolated environment.
        Returns a dictionary with: stdout, stderr, exit_code, duration_ms, and side_effects.
        """
        pass

    @abstractmethod
    def cleanup(self, context: ExecutionContext):
        """
        Cleans up resources (containers, processes, workspaces) for a given context.
        """
        pass

    def get_state(self, context: ExecutionContext) -> Dict[str, Any]:
        """
        Optional: Returns the current state of the isolated environment.
        """
        return {}
