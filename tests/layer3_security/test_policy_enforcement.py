import pytest
from core.ucer import UCER, ExecutionStep
from security.policy import PolicySentinel

def test_sentinel_blocks_unauthorized_commands():
    sentinel = PolicySentinel()
    
    # Simulate a malformed/malicious UCER injection
    malicious_ucer = UCER(
        intent="Delete logs",
        steps=[
            ExecutionStep(adapter="bash", command="rm -rf /var/log")
        ]
    )
    
    is_safe, reason = sentinel.audit_ucer(malicious_ucer)
    assert not is_safe
    assert "Destructive command blocked" in reason or "rm -rf" in reason

def test_sentinel_allows_benign_commands():
    sentinel = PolicySentinel()
    
    benign_ucer = UCER(
        intent="Read logs",
        steps=[
            ExecutionStep(adapter="bash", command="cat /var/log/syslog")
        ]
    )
    
    is_safe, _ = sentinel.audit_ucer(benign_ucer)
    assert is_safe
