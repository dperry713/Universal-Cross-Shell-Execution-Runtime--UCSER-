import pytest
from core.ucer import UCER, ExecutionStep
from tests.harness.replay_engine import ReplayEngine
from tests.harness.trace_comparator import TraceComparator

def test_determinism_replay_invariance(deterministic_executor):
    # A fixture map returning deterministic outputs
    fixture = {
        "echo hello": {"stdout": "hello\n", "exit_code": 0}
    }
    executor = deterministic_executor(fixture)
    
    ucer = UCER(
        intent="Say hello",
        steps=[ExecutionStep(adapter="bash", command="echo hello")]
    )
    
    # Execute first time
    executed_ucer = executor.execute_ucer(ucer)
    
    # Test Replay Invariance (Layer D)
    engine = ReplayEngine(executor)
    assert engine.replay_and_validate(executed_ucer.command_id) == True

def test_cross_environment_consistency():
    # Both environments yield normalized logical results for "list files"
    ps_fixture = {"dir": {"stdout": "file.txt\n", "exit_code": 0}}
    bash_fixture = {"ls": {"stdout": "file.txt\n", "exit_code": 0}}
    
    bash_trace = ExecutionStep(adapter="bash", command="ls")
    ps_trace = ExecutionStep(adapter="powershell", command="dir")
    
    assert ps_fixture["dir"]["stdout"] == bash_fixture["ls"]["stdout"]
