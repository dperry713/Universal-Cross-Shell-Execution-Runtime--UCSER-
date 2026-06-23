from core.ucer import UCER
from semantic.llm_client import LLMClient, ResilientSemanticCompiler
from security.policy import PolicyGate
from semantic.capabilities import CapabilityMapper
from core.config import config
from utils.observability.logging import get_logger
from core.types import ExecutionContext
from typing import Optional

logger = get_logger(__name__, level=config.log_level)

class SemanticCompilerFacade:
    """
    High-integrity Semantic Compiler for UCSER.
    Orchestrates LLM-to-UCER translation with automated capability discovery.
    """
    def __init__(self, llm_client: LLMClient, policy_gate: PolicyGate = None):
        self.resilient_compiler = ResilientSemanticCompiler(llm_client)
        self.policy_gate = policy_gate or PolicyGate()

    def compile(self, intent: str, context: Optional[ExecutionContext] = None) -> UCER:
        """
        Translates a natural language intent into a verified UCER.
        """
        logger.info("Compiling intent", extra={"intent": intent})
        
        # 1. Resilient LLM Translation (with Tenacity retries)
        ucer = self.resilient_compiler.compile_intent(intent, UCER)
        
        # 2. Automated Capability Discovery (AST-based)
        ucer.required_capabilities = CapabilityMapper.resolve_ucer_capabilities(ucer.model_dump())
        
        # 3. Security Policy Evaluation
        try:
            self.policy_gate.evaluate(ucer, context=context)
        except Exception as e:
            logger.error("Security Gate Blocked Compilation", extra={
                "intent": intent,
                "error": str(e)
            })
            raise PermissionError(f"Semantic Security Violation: {e}")
            
        logger.info("Successfully compiled intent to UCER", extra={"command_id": ucer.command_id})
        return ucer
class SemanticCompiler(SemanticCompilerFacade): pass
