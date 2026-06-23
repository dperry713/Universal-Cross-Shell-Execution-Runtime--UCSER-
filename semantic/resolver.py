import platform
import os
from typing import Optional

class SemanticResolver:
    """
    Intelligently selects the optimal shell environment based on intent and OS.
    Ensures portability across diverse execution nodes.
    """
    
    @staticmethod
    def get_preferred_adapter() -> str:
        """Returns the native shell for the current operating system."""
        system = platform.system().lower()
        if system == "windows":
            return "powershell"
        return "bash"

    @staticmethod
    def resolve_adapter_for_command(command: str) -> str:
        """
        Heuristically selects an adapter based on command signatures.
        """
        # PowerShell signatures
        if any(x in command for x in ["Get-", "Set-", "Invoke-", "Start-", "$env:"]):
            return "powershell"
        
        # Bash signatures
        if any(x in command for x in ["ls -", "grep ", "sudo ", "apt-get"]):
            return "bash"
            
        return SemanticResolver.get_preferred_adapter()

    @staticmethod
    def resolve_binary_path(binary: str) -> Optional[str]:
        """Cross-platform binary path resolution."""
        # This would interface with a more complex NodeRegistry in Phase 5
        return shutil.which(binary)
