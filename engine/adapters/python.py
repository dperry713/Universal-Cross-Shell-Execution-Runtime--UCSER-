from engine.adapters.base import BaseAdapter
from engine.executor import run_subprocess

class PythonAdapter(BaseAdapter):
    def name(self) -> str:
        return "python"

    def execute(self, command_id: str, command: str, timeout: int = 5):
        # Isolated Python Execution - Hardened against injection
        # We pass the command as a single argument to avoid shell interpolation risks
        return run_subprocess(
            command_id,
            self.name(),
            ["python", "-c", command],
            shell=False,
            timeout=timeout
        )
