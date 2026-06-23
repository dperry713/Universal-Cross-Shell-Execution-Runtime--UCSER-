import pytest
from semantic.compiler import SemanticCompiler
from semantic.llm_client import MockLLMClient
from core.types import Capability, ExecutionContext
from core.ucer import UCER

def test_semantic_compilation_with_capability_discovery():
    # Setup
    llm = MockLLMClient()
    compiler = SemanticCompiler(llm)
    
    # Intent that triggers standard discovery
    intent = "Get all running processes on windows"
    context = ExecutionContext(capabilities={Capability.EXEC, Capability.FS_READ})
    
    # 1. Compile
    ucer = compiler.compile(intent, context=context)
    
    # 2. Verify
    assert ucer.intent == intent
    assert ucer.status == "pending"
    # Verify that CapabilityMapper resolved EXEC based on the Get-Process command in MockLLMClient
    assert Capability.EXEC in ucer.required_capabilities
    assert len(ucer.steps) > 0
    assert ucer.steps[0].adapter == "powershell"

def test_semantic_security_rejection():
    llm = MockLLMClient()
    compiler = SemanticCompiler(llm)
    
    # Intent that results in forbidden command (MockLLM doesn't do this by default, 
    # so we'll mock the internal client response for this test)
    from unittest.mock import MagicMock
    llm.to_ucer = MagicMock(return_value={
        "command_id": "malicious-id",
        "intent": "delete everything",
        "steps": [{"step_id": "1", "adapter": "bash", "command": "rm -rf /"}]
    })
    
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    with pytest.raises(PermissionError) as excinfo:
        compiler.compile("delete everything", context=context)
    
    assert "Semantic Security Violation" in str(excinfo.value)
    assert "Forbidden command detected: rm" in str(excinfo.value)
