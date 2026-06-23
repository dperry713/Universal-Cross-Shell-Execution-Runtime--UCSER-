import pytest
from core.distributed import DistributedNodeManager
from core.ucer import UCER, ExecutionStep
from core.types import Capability, ExecutionContext
from core.executor import UniversalExecutor
from core.db import Database
from unittest.mock import MagicMock

def test_isolation_negotiation_logic():
    manager = DistributedNodeManager()
    
    # 1. Low Risk -> Docker
    ucer_low = UCER(intent="low risk", steps=[], required_capabilities={Capability.EXEC})
    assert manager.negotiate_isolation(ucer_low) == "docker"
    
    # 2. High Risk (NETWORK) -> MicroVM
    ucer_high = UCER(intent="high risk", steps=[], required_capabilities={Capability.NETWORK})
    assert manager.negotiate_isolation(ucer_high) == "microvm"

@pytest.mark.asyncio
async def test_executor_isolation_routing(tmp_path):
    db_path = tmp_path / "isolation.db"
    db = Database(str(db_path))
    executor = UniversalExecutor(db=db)
    
    # Mock adapters
    mock_docker = MagicMock()
    mock_docker.run.return_value = {"stdout": "docker-exec", "exit_code": 0}
    mock_mvm = MagicMock()
    mock_mvm.run.return_value = {"stdout": "mvm-exec", "exit_code": 0}
    
    executor.unified.adapters["bash"] = mock_docker
    executor.unified.adapters["microvm"] = mock_mvm
    
    # 1. Test Routing to MicroVM
    ucer_net = UCER(
        intent="Network access",
        steps=[ExecutionStep(adapter="bash", command="curl ...")]
    )
    # Force the required_capabilities (normally handled by compiler)
    ucer_net.required_capabilities = {Capability.NETWORK, Capability.EXEC}
    
    context = ExecutionContext(capabilities={Capability.NETWORK, Capability.EXEC})
    
    await executor.execute_ucer(ucer_net, context=context)
    
    # Verify that microvm adapter was called even though step said 'bash'
    mock_mvm.run.assert_called_once()
    mock_docker.run.assert_not_called()
    assert ucer_net.traces[0].adapter == "microvm"
