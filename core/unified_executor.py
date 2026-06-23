from typing import Dict, Any, Set
from core.types import Capability, ExecutionContext

class UnifiedExecutor:
    def __init__(self, auditors, policy_engine, adapters):
        self.auditors = auditors
        self.policy = policy_engine
        self.adapters = adapters

    def execute(self, shell: str, command: str, context: ExecutionContext) -> Dict[str, Any]:
        if shell not in self.auditors or shell not in self.adapters:
            raise ValueError(f"Unsupported shell or missing components for: {shell}")

        # 1. Enforcement via PolicyGate (Phase 4 Structural Overhaul)
        # Wrap command in a temporary UCER for policy evaluation
        from core.ucer import UCER, ExecutionStep
        temp_ucer = UCER(intent="unified_exec", steps=[ExecutionStep(adapter=shell, command=command)])
        self.policy.evaluate(temp_ucer, context)

        # 2. Parse into AST for rewriting
        ast = self.auditors[shell].parse(command)

        # 3. Rewrite (Audit / Sanitize)
        audited_command = self.auditors[shell].rewrite(command, ast)

        # 4. Execute via Adapter
        return self.adapters[shell].run(audited_command, context)
