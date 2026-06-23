from typing import Any

from core.config import config
from core.dsl import (
    ExecuteCommandIntent,
    NetworkRequestIntent,
    ReadFileIntent,
    WriteFileIntent,
)
from core.types import Capability, ExecutionContext
from security.auditor import BashASTAuditor
from security.contract import FormalContract
from security.ps_daemon import PersistentPowerShellAuditor
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)


class PolicyGate:
    """
    Orchestrates the formal evaluation of a UCER against security policies using AST auditors.
    """

    def __init__(self):
        self.bash_auditor = BashASTAuditor()
        self.ps_auditor = PersistentPowerShellAuditor()

    @FormalContract.requires({Capability.EXEC})
    def evaluate(
        self, ucer: Any, context: ExecutionContext, allowed_caps: set[Capability] | None = None
    ):
        # 1. Establish the maximum allowed boundary from context
        context_caps = context.capabilities if context else set()

        # 2. If allowed_caps is passed, it must be a strict subset of context_caps
        if allowed_caps is not None:
            if not allowed_caps.issubset(context_caps):
                violation = allowed_caps - context_caps
                raise PermissionError(
                    f"Security Gate Blocked Execution: Explicit allowed_caps {violation} exceed context boundary."
                )
        else:
            # Default to context caps or a safe minimal set if no context
            allowed_caps = (
                context_caps
                if context
                else {Capability.FS_READ, Capability.EXEC, Capability.EXECUTE_READ}
            )

        for step in ucer.steps:
            auditor = self.bash_auditor if step.adapter in ["bash", "linux"] else self.ps_auditor
            result = auditor.audit(step.command)

            # Aggregate required capabilities into the UCER record
            ucer.required_capabilities.update(result.capabilities)

            if not result.capabilities.issubset(allowed_caps):
                violation = result.capabilities - allowed_caps
                logger.error(
                    "Security Policy Violation",
                    extra={
                        "command_id": ucer.command_id,
                        "reasons": [f"Unauthorized capabilities {violation}"],
                        "missing_capabilities": [cap.value for cap in violation],
                    },
                )
                raise PermissionError(
                    f"Security Gate Blocked Execution: Unauthorized capabilities {violation}"
                )

            if not result.is_safe:
                logger.error(
                    "Security Policy Violation",
                    extra={"command_id": ucer.command_id, "reasons": result.reasons},
                )
                raise PermissionError(
                    f"Security Gate Blocked Execution: {'; '.join(result.reasons)}"
                )

        logger.info("Security Gate Passed", extra={"command_id": ucer.command_id})


class PolicyEngine:
    """
    Backwards-compatible helper that exposes the legacy capability mapping helpers.
    """

    def __init__(self):
        self.bash_auditor = BashASTAuditor()
        self.ps_auditor = PersistentPowerShellAuditor()

    def map_capabilities_from_dsl(self, intents):
        capabilities = set()
        for intent in intents:
            if isinstance(intent, WriteFileIntent):
                capabilities.add(Capability.WRITE_FS)
            elif isinstance(intent, ReadFileIntent):
                capabilities.add(Capability.FS_READ)
            elif isinstance(intent, ExecuteCommandIntent):
                capabilities.add(Capability.EXEC)
            elif isinstance(intent, NetworkRequestIntent):
                capabilities.add(Capability.NETWORK)
        return capabilities

    def map_capabilities(self, ast: Any, adapter: str):
        capabilities = set()
        commands = []
        for node in getattr(ast, "nodes", []):
            command = getattr(node, "command", None)
            if command:
                commands.append(command)

        if adapter in {"bash", "linux"}:
            auditor = self.bash_auditor
            for command in commands:
                capabilities.update(auditor.audit(command).capabilities)
        else:
            lowered_commands = [command.lower() for command in commands]
            for command in lowered_commands:
                if any(
                    token in command
                    for token in ["invoke-webrequest", "iwr", "curl", "wget", "irm"]
                ):
                    capabilities.add(Capability.NETWORK)
                if any(token in command for token in ["remove-item", "rm ", "del ", "erase "]):
                    capabilities.add(Capability.WRITE_FS)
                if any(token in command for token in ["get-process", "dir", "ls", "cat"]):
                    capabilities.add(Capability.FS_READ)
                capabilities.add(Capability.EXEC)

        return capabilities

    def is_allowed(self, requested, allowed):
        return set(requested).issubset(set(allowed))


class PolicySentinel:
    """
    Legacy sentinel facade used by older tests.
    """

    def __init__(self):
        self.policy_gate = PolicyGate()

    def audit_ucer(self, ucer):
        try:
            context = ExecutionContext(capabilities={Capability.EXEC, Capability.FS_READ})
            self.policy_gate.evaluate(ucer, context=context)
            return True, "allowed"
        except Exception as exc:
            for step in getattr(ucer, "steps", []):
                command = getattr(step, "command", "")
                if any(
                    token in command.lower()
                    for token in ["rm ", "rm -rf", "shred", "unlink", "mkfs", "dd"]
                ):
                    return False, f"Destructive command blocked: {command}"
            return False, str(exc)
