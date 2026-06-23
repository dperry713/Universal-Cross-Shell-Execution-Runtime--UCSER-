from typing import Set, List, Any, Optional
from core.types import Capability, ExecutionContext
from core.config import config
from utils.observability.logging import get_logger
from security.auditor import BashASTAuditor
from security.ps_daemon import PersistentPowerShellAuditor

from security.contract import FormalContract

logger = get_logger(__name__, level=config.log_level)

class PolicyGate:
    """
    Orchestrates the formal evaluation of a UCER against security policies using AST auditors.
    """
    def __init__(self):
        self.bash_auditor = BashASTAuditor()
        self.ps_auditor = PersistentPowerShellAuditor()

    @FormalContract.requires({Capability.EXEC})
    def evaluate(self, ucer: Any, context: ExecutionContext, allowed_caps: Optional[Set[Capability]] = None):
        # 1. Establish the maximum allowed boundary from context
        context_caps = context.capabilities if context else set()

        # 2. If allowed_caps is passed, it must be a strict subset of context_caps
        if allowed_caps is not None:
            if not allowed_caps.issubset(context_caps):
                violation = allowed_caps - context_caps
                raise PermissionError(f"Security Gate Blocked Execution: Explicit allowed_caps {violation} exceed context boundary.")
        else:
            # Default to context caps or a safe minimal set if no context
            allowed_caps = context_caps if context else {Capability.FS_READ, Capability.EXEC, Capability.EXECUTE_READ}

        for step in ucer.steps:
            auditor = self.bash_auditor if step.adapter in ['bash', 'linux'] else self.ps_auditor
            result = auditor.audit(step.command)
            
            # Aggregate required capabilities into the UCER record
            ucer.required_capabilities.update(result.capabilities)
            
            if not result.is_safe:
                logger.error("Security Policy Violation", extra={
                    "command_id": ucer.command_id,
                    "reasons": result.reasons
                })
                raise PermissionError(f"Security Gate Blocked Execution: {'; '.join(result.reasons)}")
            
            if not result.capabilities.issubset(allowed_caps):
                violation = result.capabilities - allowed_caps
                raise PermissionError(f"Security Gate Blocked Execution: Unauthorized capabilities {violation}")

        logger.info("Security Gate Passed", extra={"command_id": ucer.command_id})

