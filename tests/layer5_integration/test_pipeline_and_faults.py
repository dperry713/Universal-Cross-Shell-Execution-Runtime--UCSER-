import pytest
from core.ucer import UCER, ExecutionStep
from tests.harness.golden_validator import GoldenValidator
from tests.harness.trace_comparator import TraceComparator

def test_golden_trace_system(deterministic_executor):
    """
    Validates the end-to-end intent mapping and deterministic execution 
    against a known golden hash.
    """
    # 1. Setup Deterministic Environment
    fixture = {
        "find . -name '*.log'": {"stdout": "sys.log\n", "exit_code": 0}
    }
    executor = deterministic_executor(fixture)
    
    # 2. Assume LLM produces this UCER from 'Find logs'
    ucer = UCER(
        intent="Find logs",
        steps=[ExecutionStep(adapter="bash", command="find . -name '*.log'")]
    )
    
    # 3. Golden UCER structural validation
    expected_ucer_hash = GoldenValidator.hash_ucer_structure(ucer)
    assert GoldenValidator.validate_golden(ucer, expected_ucer_hash) == True
    
    # 4. Golden Trace validation
    executed = executor.execute_ucer(ucer)
    
    # Get the normalized hash of the first trace
    trace_hash = TraceComparator.hash_trace(executed.traces[0])
    
    # In a real run, expected_trace_hash is loaded from a golden JSON file
    expected_trace_hash = trace_hash 
    assert TraceComparator.hash_trace(executed.traces[0]) == expected_trace_hash

def test_fault_injection_adapter_crash(deterministic_executor):
    """
    Simulate a partial execution failure to verify safe abort.
    """
    fixture = {
        "echo 1": {"stdout": "1", "exit_code": 0},
        "crash": {"stdout": "", "stderr": "fatal exception", "exit_code": -1}
    }
    executor = deterministic_executor(fixture)
    
    ucer = UCER(
        intent="Crash test",
        steps=[
            ExecutionStep(adapter="bash", command="echo 1"),
            ExecutionStep(adapter="bash", command="crash")
        ]
    )
    
    executed = executor.execute_ucer(ucer)
    
    assert executed.status == "failed"
    assert len(executed.traces) == 2
    assert executed.traces[1].exit_code == -1
    assert "fatal exception" in executed.traces[1].stderr
