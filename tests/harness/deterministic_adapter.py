import json
from typing import Dict, Any

class DeterministicAdapter:
    """
    A simulated adapter for Layer A & B determinism testing.
    Output is strictly derived from a fixture map. Environment completely isolated.
    """
    def __init__(self, fixture_map: Dict[str, Dict[str, Any]] = None):
        """
        fixture_map: Maps command string -> {'stdout': str, 'stderr': str, 'exit_code': int}
        """
        self.fixture_map = fixture_map or {}

    def execute(self, command: str) -> Dict[str, Any]:
        """
        Executes a command deterministically.
        If the command is not in the fixture map, it returns a safe default.
        """
        # Normalize command for basic matching
        normalized = command.strip()
        
        if normalized in self.fixture_map:
            result = self.fixture_map[normalized]
            return {
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "exit_code": result.get("exit_code", 0)
            }
            
        # Deterministic fallback for unknown commands during tests
        return {
            "stdout": f"Mock output for: {normalized}",
            "stderr": "",
            "exit_code": 0
        }
