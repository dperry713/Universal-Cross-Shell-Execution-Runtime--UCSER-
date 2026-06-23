import pytest
from semantic.compiler import SemanticCompiler
from semantic.llm_client import LLMClient
from core.ucer import UCER

class MockLLMClient(LLMClient):
    def to_ucer(self, intent: str) -> dict:
        # We enforce that the exact same intent produces the exact same mock response.
        # This tests our compilation layer's schema mapping.
        if "log files" in intent:
            return {
                "command_id": "test-uuid",
                "intent": intent,
                "steps": [
                    {"step_id": "step1", "adapter": "bash", "command": "find . -name '*.log'"}
                ]
            }
        return {"intent": intent, "steps": []}

def test_semantic_determinism():
    compiler = SemanticCompiler(llm_client=MockLLMClient())
    ucer1 = compiler.compile("Find all log files")
    ucer2 = compiler.compile("Find all log files")
    
    # Dump without timestamps or other random values that shouldn't affect semantics
    dump1 = ucer1.model_dump(exclude={'timestamp'})
    dump2 = ucer2.model_dump(exclude={'timestamp'})
    assert dump1 == dump2
    assert ucer1.steps[0].adapter == "bash"

def test_critical_constraints_capabilities():
    # If a command implies read, we assert the UCER output doesn't contain destructive steps.
    compiler = SemanticCompiler(llm_client=MockLLMClient())
    ucer = compiler.compile("Find all log files")
    
    assert "rm" not in ucer.steps[0].command
