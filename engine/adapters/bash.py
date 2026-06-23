from engine.adapters.base import BaseAdapter
from engine.executor import run_subprocess

class BashAdapter(BaseAdapter):
    def name(self) -> str:
        return "bash"

    def execute(self, command_id: str, command: str, timeout: int = 5):
        # NOTE: On Windows, /bin/bash might not exist if WSL isn't configured for it natively.
        # However, relying on GitBash's bash.exe or assuming WSL 'bash' is standard for this architecture.
        # We will use "bash" as the executable.
        return run_subprocess(
            command_id,
            self.name(),
            command,
            shell="bash", 
            timeout=timeout
        )
