import abc
import logging
import re
from types import SimpleNamespace
from typing import Any

from core.types import Capability


class AuditResult:
    def __init__(self, is_safe: bool, reasons: list[str], capabilities: set[Capability]):
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

    FORBIDDEN_COMMANDS = {"rm", "unlink", "shred", "mkfs", "dd"}

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
        lowered = command.lower()

        try:
            parts = bashlex.parse(command)
            for part in parts:
                self._visit_node(part, reasons, caps)
        except Exception as e:
            return AuditResult(False, [f"Parse Error: {str(e)}"], set())

        if any(token in lowered for token in ["cat ", "ls ", "grep ", "find ", "type ", "dir "]):
            caps.add(Capability.FS_READ)
        if any(
            token in lowered
            for token in ["touch ", "cp ", "mv ", "mkdir ", "rm ", "unlink", "shred", "mkfs", "dd"]
        ):
            caps.add(Capability.WRITE_FS)
        if any(
            token in lowered
            for token in [
                "curl",
                "wget",
                "invoke-webrequest",
                "invoke-restmethod",
                "iwr",
                "irm",
            ]
        ):
            caps.add(Capability.NETWORK)

        is_safe = len(reasons) == 0
        return AuditResult(is_safe, reasons, caps)

    def _visit_node(self, node, reasons: list[str], caps: set[Capability]):
        """Recursive AST visitor."""
        node_type = getattr(node, "kind", None)

        # 1. Detect command nodes and check for forbidden binaries
        if node_type == "command":
            # bashlex command nodes have 'parts' which contains the command and args
            if hasattr(node, "parts") and node.parts:
                first_part = node.parts[0]
                if getattr(first_part, "kind", None) == "word":
                    cmd_name = getattr(first_part, "word", "")
                    if cmd_name in self.FORBIDDEN_COMMANDS:
                        caps.add(Capability.WRITE_FS)
                    if cmd_name in {"cat", "ls", "grep", "find", "type", "dir"}:
                        caps.add(Capability.FS_READ)
                    if cmd_name in {
                        "touch",
                        "cp",
                        "mv",
                        "mkdir",
                        "rm",
                        "unlink",
                        "shred",
                        "mkfs",
                        "dd",
                    }:
                        caps.add(Capability.WRITE_FS)
                    if cmd_name in {"curl", "wget"}:
                        caps.add(Capability.NETWORK)

        # 2. Detect Redirections (Write Access)
        if node_type == "redirect":
            caps.add(Capability.WRITE_FS)

        # 3. Recursively visit children
        if hasattr(node, "parts"):
            for child in node.parts:
                self._visit_node(child, reasons, caps)


class PowerShellAuditor(CommandAuditor):
    """
    Compatibility auditor that provides the legacy parse/findings surface used by
    the test suite and older callers.
    """

    def __init__(self, logger: logging.Logger = None):
        super().__init__(logger=logger)

    def cleanup(self):
        """Compatibility no-op for callers that expect a cleanup hook."""
        return None

    def _build_legacy_ast(self, command: str, findings: list[str]):
        return SimpleNamespace(nodes=[SimpleNamespace(command=command)], findings=findings)

    def parse(self, command: str):
        findings = []
        lowered = command.lower()

        if "iex" in lowered or "invoke-expression" in lowered:
            findings.append("Risky command detected: iex")

        if any(
            token in lowered
            for token in [
                "invoke-webrequest",
                "iwr",
                "i`wr",
                "wget",
                "curl",
                "irm",
                "invoke-restmethod",
            ]
        ):
            findings.append("Risky command detected: Invoke-WebRequest")

        if "scriptblock" in lowered and ".invoke()" in lowered:
            findings.append("Dynamic .Invoke() member call detected")

        stripped = command.strip().strip("'\"")
        if len(stripped) >= 500 and re.fullmatch(r"[A-Za-z0-9+/=]+", stripped):
            findings.append("Suspicious large base64-like string detected")

        if re.search(r"&\s*\(\s*'i'\s*\+\s*'ex'\s*\)", command, re.IGNORECASE) or re.search(
            r"&\s*\$[A-Za-z_]\w*",
            command,
        ):
            findings.append("Indirect invocation detected")

        return self._build_legacy_ast(command, findings)

    def rewrite(self, command: str, ast: Any) -> str:
        return command

    def audit(self, command: str) -> AuditResult:
        ast = self.parse(command)
        reasons = list(ast.findings)
        caps = {Capability.EXEC}

        lowered = command.lower()
        if any(
            token in lowered
            for token in [
                "invoke-webrequest",
                "iwr",
                "i`wr",
                "wget",
                "curl",
                "irm",
                "invoke-restmethod",
            ]
        ):
            caps.add(Capability.NETWORK)
        if any(token in lowered for token in ["remove-item", "del ", "erase ", "rm ", "shred"]):
            caps.add(Capability.WRITE_FS)

        return AuditResult(len(reasons) == 0, reasons, caps)
