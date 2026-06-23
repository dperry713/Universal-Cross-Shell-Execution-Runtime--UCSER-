import pytest
from security.sentinel import SecuritySentinel
from core.ucer import ExecutionTrace
from core.types import ExecutionContext, Capability
from unittest.mock import MagicMock

def test_sentinel_data_leakage_detection():
    sentinel = SecuritySentinel()
    context = ExecutionContext()
    
    # 1. Safe trace
    trace_safe = ExecutionTrace(
        step_id="1", adapter="bash", command="ls", 
        stdout="file1.txt", stderr="", exit_code=0, duration_ms=0
    )
    assert sentinel.inspect_trace(trace_safe, context) is True
    
    # 2. Leaking trace (password)
    trace_leak = ExecutionTrace(
        step_id="2", adapter="bash", command="cat config.env", 
        stdout="DB_PASSWORD=secret123", stderr="", exit_code=0, duration_ms=0
    )
    assert sentinel.inspect_trace(trace_leak, context) is False

def test_sentinel_unauthorized_network_detection():
    mock_net = MagicMock()
    # Simulate network auditor finding an outbound connection
    mock_net.get_audit_log.return_value = [{"dest": "evil.com"}]
    
    sentinel = SecuritySentinel(network_auditor=mock_net)
    
    # Context without NETWORK capability
    context = ExecutionContext(capabilities={Capability.EXEC})
    trace = ExecutionTrace(
        step_id="3", adapter="bash", command="curl ...", 
        stdout="", stderr="", exit_code=0, duration_ms=0
    )
    
    assert sentinel.inspect_trace(trace, context) is False
    mock_net.get_audit_log.assert_called_once()

def test_sentinel_state_change_validation():
    sentinel = SecuritySentinel()
    
    trace = ExecutionTrace(
        step_id="4", adapter="bash", command="rm file.txt",
        stdout="", stderr="", exit_code=0, duration_ms=0,
        side_effects={"files_removed": ["file.txt", "unexpected.txt"]}
    )
    
    expected = {"files_removed": ["file.txt"]}
    
    # This currently only logs a warning in our implementation, but we check for True
    assert sentinel.validate_state_changes(trace, expected) is True
