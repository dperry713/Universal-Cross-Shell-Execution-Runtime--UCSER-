import abc
import json
import logging
from typing import Tuple, List, Set, Any
from core.types import Capability

class AuditResult:
    def __init__(self, is_safe: bool, reasons: List[str], capabilities: Set[Capability]):
        self.is_safe = is_safe
        self.reasons = reasons
        self.capabilities = capabilities

class CommandAuditor(abc.ABC):
    """
    Base class for AST-based command auditing.
    """
    def __init__(self, logger: logging.Logger = None):
        self.logger = logger or logging.getLogger(self.__class__.__name__)

    @abc.abstractmethod
    def audit(self, command: str) -> AuditResult:
        """
        Parses the command into an AST and evaluates security risks.
        """
        pass

class BashASTAuditor(CommandAuditor):
    """
    Uses bashlex to perform structural analysis on Bash commands.
    """
    FORBIDDEN_COMMANDS = {'rm', 'unlink', 'shred', 'mkfs', 'dd'}
    
    def parse(self, command: str):
        import bashlex
        try:
            parts = bashlex.parse(command)
            # Create a wrapper object that matches the legacy expectation
            class LegacyAST:
                def __init__(self, parts, findings):
                    self.nodes = parts
                    self.findings = findings
            
            audit_res = self.audit(command)
            return LegacyAST(parts, audit_res.reasons if not audit_res.is_safe else [])
        except Exception as e:
            class ErrorAST:
                def __init__(self, error):
                    self.nodes = []
                    self.findings = [f"Parse Error: {str(error)}"]
            return ErrorAST(e)

    def rewrite(self, command: str, ast: Any) -> str:
        """Zero shell-interpolation: return command exactly as audited."""
        return command

    def audit(self, command: str) -> AuditResult:
        import bashlex
        reasons = []
        caps = {Capability.EXEC}
        
        try:
            parts = bashlex.parse(command)
            for part in parts:
                self._visit_node(part, reasons, caps)
        except Exception as e:
            return AuditResult(False, [f"Parse Error: {str(e)}"], set())

        is_safe = len(reasons) == 0
        return AuditResult(is_safe, reasons, caps)

    def _visit_node(self, node, reasons: List[str], caps: Set[Capability]):
        """Recursive AST visitor."""
        node_type = getattr(node, 'kind', None)
        
        # 1. Detect command nodes and check for forbidden binaries
        if node_type == 'command':
            # bashlex command nodes have 'parts' which contains the command and args
            if hasattr(node, 'parts') and node.parts:
                first_part = node.parts[0]
                if getattr(first_part, 'kind', None) == 'word':
                    cmd_name = getattr(first_part, 'word', '')
                    if cmd_name in self.FORBIDDEN_COMMANDS:
                        reasons.append(f"Forbidden command detected: {cmd_name}")
                        caps.add(Capability.DELETE_ROOT)
        
        # 2. Detect Redirections (Write Access)
        if node_type == 'redirect':
             caps.add(Capability.WRITE_FS)

        # 3. Recursively visit children
        if hasattr(node, 'parts'):
            for child in node.parts:
                self._visit_node(child, reasons, caps)
