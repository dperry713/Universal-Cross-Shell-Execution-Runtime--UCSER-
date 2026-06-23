from core.config import config
from core.types import Capability, ExecutionContext
from core.ucer import UCER
from security.policy import PolicyGate
from semantic.capabilities import CapabilityMapper
from semantic.llm_client import LLMClient, ResilientSemanticCompiler
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)


class SemanticCompilerFacade:
    """
    High-integrity Semantic Compiler for UCSER.
    Orchestrates LLM-to-UCER translation with automated capability discovery.
    """

    def __init__(self, llm_client: LLMClient, policy_gate: PolicyGate | None = None):
        self.resilient_compiler = ResilientSemanticCompiler(llm_client)
        self.policy_gate = policy_gate or PolicyGate()

    def compile(self, intent: str, context: ExecutionContext | None = None) -> UCER:
        """
        Translates a natural language intent into a verified UCER.
        """
        logger.info("Compiling intent", extra={"intent": intent})

        active_context = context or ExecutionContext(
            capabilities={Capability.EXEC, Capability.FS_READ}
        )

        # 1. Resilient LLM Translation (with Tenacity retries)
        ucer = self.resilient_compiler.compile_intent(intent, UCER)

        # 2. Automated Capability Discovery (AST-based)
        ucer.required_capabilities = CapabilityMapper.resolve_ucer_capabilities(ucer.model_dump())

        # 3. Security Policy Evaluation
        try:
            self.policy_gate.evaluate(ucer, context=active_context)
        except Exception as e:
            logger.error(
                "Security Gate Blocked Compilation", extra={"intent": intent, "error": str(e)}
            )
            raise PermissionError(f"Semantic Security Violation: {e}") from e

        logger.info("Successfully compiled intent to UCER", extra={"command_id": ucer.command_id})
        return ucer


class SemanticCompiler(SemanticCompilerFacade):
    pass
