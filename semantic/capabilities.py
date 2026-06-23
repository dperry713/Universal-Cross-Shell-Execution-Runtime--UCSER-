from core.types import Capability
from security.auditor import BashASTAuditor
from security.ps_daemon import PersistentPowerShellAuditor


class CapabilityMapper:
    """
    Structural Capability Resolver for UCSER.
    Uses AST-based analysis to determine required security tokens.
    """

    _bash_auditor = BashASTAuditor()
    _ps_auditor = PersistentPowerShellAuditor()

    @classmethod
    def resolve_for_command(cls, command: str, adapter: str | None = None) -> set[Capability]:
        """
        Determines required capabilities by performing a dry-run audit of the command.
        """
        if adapter is None:
            lowered = command.lower()
            adapter = (
                "powershell"
                if any(token in lowered for token in ["get-", "set-", "invoke-", "foreach-object"])
                else "bash"
            )

        auditor = cls._bash_auditor if adapter in ["bash", "linux"] else cls._ps_auditor
        result = auditor.audit(command)

        # Return the structural capabilities discovered by the AST visitor
        return result.capabilities

    @classmethod
    def resolve_ucer_capabilities(cls, ucer_data: dict) -> set[Capability]:
        """
        Aggregates required capabilities across all steps in a UCER payload.
        """
        total_caps: set[Capability] = set()
        steps = ucer_data.get("steps", [])
        for step in steps:
            total_caps.update(cls.resolve_for_command(step["command"], step["adapter"]))
        return total_caps
