import sys
import os
import shutil
import pytest
from security.auditor import BashASTAuditor
from security.ps_daemon import PersistentPowerShellAuditor
from engine.state_manager import StateSnapshot
from core.types import Capability, ExecutionContext
from core.ucer import UCER, ExecutionStep
from semantic.llm_client import ResilientSemanticCompiler

def test_bash_auditor():
    auditor = BashASTAuditor()
    
    # Safe command
    res = auditor.audit("echo 'hello world'")
    assert res.is_safe
    assert Capability.EXEC in res.capabilities
    
    # Forbidden command
    res = auditor.audit("rm -rf /")
    assert not res.is_safe
    assert "Forbidden command detected: rm" in res.reasons
    assert Capability.DELETE_ROOT in res.capabilities

    # Redirection
    res = auditor.audit("echo 'data' > output.log")
    assert res.is_safe
    assert Capability.WRITE_FS in res.capabilities

def test_ps_auditor():
    auditor = PersistentPowerShellAuditor(port=60001)
    try:
        # Safe command
        res = auditor.audit("Get-Process")
        assert res.is_safe
        
        # Risky command
        res = auditor.audit("Invoke-WebRequest http://evil.com")
        assert not res.is_safe
        assert any("Risky cmdlet" in r for r in res.reasons)
    finally:
        if auditor.daemon_proc:
            auditor.daemon_proc.terminate()

def test_state_snapshot_rollback():
    test_dir = "./test_runtime_space"
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    os.makedirs(test_dir)
    
    try:
        # Create initial state
        with open(os.path.join(test_dir, "keep.txt"), "w") as f:
            f.write("original")
        
        snapshot = StateSnapshot(test_dir)
        snapshot.capture_backup()
        
        # Mutate state
        with open(os.path.join(test_dir, "temp.txt"), "w") as f:
            f.write("delete me")
        os.remove(os.path.join(test_dir, "keep.txt"))
        
        # Verify mutation
        assert not os.path.exists(os.path.join(test_dir, "keep.txt"))
        assert os.path.exists(os.path.join(test_dir, "temp.txt"))
        
        # Rollback
        snapshot.restore()
        
        # Verify restoration
        assert os.path.exists(os.path.join(test_dir, "keep.txt"))
        assert not os.path.exists(os.path.join(test_dir, "temp.txt"))
        with open(os.path.join(test_dir, "keep.txt"), "r") as f:
            assert f.read() == "original"
            
    finally:
        if os.path.exists(test_dir):
            shutil.rmtree(test_dir)
        # Cleanup backup paths created by StateSnapshot
        for item in os.listdir("."):
            if item.startswith("test_runtime_space_backup_"):
                shutil.rmtree(item)

class MockLLM:
    def to_ucer(self, intent):
        return {
            "command_id": "test-id",
            "intent": intent,
            "steps": [
                {
                    "step_id": "step-1",
                    "adapter": "bash",
                    "command": "echo 'verified'",
                    "expected_state_changes": {}
                }
            ]
        }

def test_resilient_compiler():
    mock = MockLLM()
    compiler = ResilientSemanticCompiler(mock)
    ucer = compiler.compile_intent("test intent", UCER)
    assert ucer.command_id == "test-id"
    assert len(ucer.steps) == 1
    assert ucer.steps[0].command == "echo 'verified'"

if __name__ == "__main__":
    # Run tests manually if not using pytest runner
    test_bash_auditor()
    print("Bash Auditor: PASSED")
    test_ps_auditor()
    print("PS Auditor: PASSED")
    test_state_snapshot_rollback()
    print("State Snapshot: PASSED")
    test_resilient_compiler()
    print("Resilient Compiler: PASSED")
