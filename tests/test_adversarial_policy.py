import pytest
from core.types import Capability, ExecutionContext
from core.ucer import UCER
from security.policy import PolicyGate

def test_adversarial_allowed_caps_escalation():
    """
    Kills VIRT_MUT_01: Verify that passing explicit allowed_caps 
    cannot exceed the ExecutionContext's defined capabilities.
    """
    gate = PolicyGate()
    # Context only has EXEC
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # Attempt to inject WRITE_FS via explicit allowed_caps
    ucer = UCER(intent="test", steps=[])
    excessive_caps = {Capability.EXEC, Capability.WRITE_FS}
    
    with pytest.raises(PermissionError) as excinfo:
        gate.evaluate(ucer, context=context, allowed_caps=excessive_caps)
    
    assert "exceed context boundary" in str(excinfo.value)
    assert "write_fs" in str(excinfo.value).lower()

def test_legitimate_allowed_caps_subset():
    """
    Verify that passing a valid subset of context capabilities passes.
    """
    gate = PolicyGate()
    # Context has both
    context = ExecutionContext(capabilities={Capability.EXEC, Capability.FS_READ})
    
    # Explicitly restrict to just EXEC for this call
    ucer = UCER(intent="test", steps=[])
    subset_caps = {Capability.EXEC}
    
    # Should not raise
    gate.evaluate(ucer, context=context, allowed_caps=subset_caps)
