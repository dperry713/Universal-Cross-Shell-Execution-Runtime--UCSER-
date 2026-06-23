from typing import Dict, Any, List
from core.config import config
from semantic.ucer import UCER, ExecutionStep, RollbackStrategy, ExpectedOutput
from semantic.capabilities import CapabilityMapper
import os
import re

class SemanticParser:
    """
    Translates raw commands or high-level intents into structured UCER representations.
    """
    
    @staticmethod
    def _determine_shell(command: str) -> str:
        """Determines the optimal execution environment for a command string."""
        if command.startswith("ps:"): return "powershell"
        if command.startswith("bash:"): return "bash"
        if command.startswith("python:"): return "python"
        
        # Heuristic fallback
        if any(x in command for x in ["Get-", "Set-", "Invoke-", "ForEach-Object"]):
            return "powershell"
        return "bash"

    @classmethod
    def parse_raw_pipeline(cls, intent: str, command_string: str) -> UCER:
        """
        Parses a traditional shell pipeline string (e.g., "ps:Get-Process | bash:grep py")
        into a sequence of isolated UCER steps.
        """
        # Intelligent pipeline splitting (preserve internal pipes)
        raw_parts = re.split(r'\|\s*(?=bash:|ps:|python:)', command_string)
        
        steps = []
        total_caps = set()
        
        for part in raw_parts:
            part = part.strip()
            if not part: continue
            
            shell = cls._determine_shell(part)
            
            # Strip prefixes for the final payload
            clean_cmd = part
            if part.startswith("ps:"): clean_cmd = part[3:].strip()
            elif part.startswith("bash:"): clean_cmd = part[5:].strip()
            elif part.startswith("python:"): clean_cmd = part[7:].strip()
            
            steps.append(ExecutionStep(
                shell=shell,
                command=clean_cmd
            ))
            
            # Aggregate required capabilities
            total_caps.update(CapabilityMapper.resolve_for_command(clean_cmd))

        return UCER(
            intent=intent,
            required_capabilities=list(total_caps),
            execution_steps=steps,
            # For raw pipelines, we expect text output by default
            expected_outputs=ExpectedOutput(format="text") 
        )

    @classmethod
    def build_intent_delete(cls, target_path: str, is_windows: bool = False) -> UCER:
        """
        Constructs a semantic 'delete' operation with a built-in rollback strategy 
        (e.g., move to temp before permanent deletion).
        """
        shell = "powershell" if is_windows else "bash"
        backup_dir = config.backup_base_dir
        
        if is_windows:
            del_cmd = f"Remove-Item -Path '{target_path}' -Recurse -Force"
            # Use centralized backup directory
            rb_cmd = f"Copy-Item -Path '{os.path.join(backup_dir, target_path)}' -Destination '{target_path}'" 
        else:
            del_cmd = f"rm -rf '{target_path}'"
            rb_cmd = f"cp -r '{os.path.join(backup_dir, target_path)}' '{target_path}'"
            
        steps = [ExecutionStep(shell=shell, command=del_cmd)]
        rollback = RollbackStrategy(
            enabled=True,
            steps=[ExecutionStep(shell=shell, command=rb_cmd, ignore_errors=True)]
        )
        
        caps = CapabilityMapper.resolve_for_command(del_cmd)
        
        return UCER(
            intent=f"Delete file/directory: {target_path}",
            required_capabilities=caps,
            execution_steps=steps,
            rollback_strategy=rollback
        )
