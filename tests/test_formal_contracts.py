import pytest
from core.types import Capability, ExecutionContext
from security.contract import FormalContract

@FormalContract.requires({Capability.WRITE_FS})
def sensitive_function(context: ExecutionContext):
    return "Accessed"

def test_contract_enforcement_pass():
    context = ExecutionContext(capabilities={Capability.WRITE_FS})
    assert sensitive_function(context=context) == "Accessed"

def test_contract_enforcement_fail():
    context = ExecutionContext(capabilities={Capability.FS_READ})
    with pytest.raises(PermissionError) as excinfo:
        sensitive_function(context=context)
    assert "Missing Capabilities: {<Capability.WRITE_FS: 'write_fs'>}" in str(excinfo.value)

def test_contract_missing_context():
    with pytest.raises(PermissionError) as excinfo:
        sensitive_function()
    assert "No ExecutionContext provided" in str(excinfo.value)
