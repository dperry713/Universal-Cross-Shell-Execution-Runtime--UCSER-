from engine.adapters.base import BaseAdapter
from engine.executor import run_subprocess

class PowerShellAdapter(BaseAdapter):
    def name(self) -> str:
        return "powershell"

    def execute(self, command_id: str, command: str, timeout: int = 5):
        # Thin wrapper around centralized executor
        return run_subprocess(
            command_id,
            self.name(),
            command,
            shell="pwsh", 
            timeout=timeout
        )
