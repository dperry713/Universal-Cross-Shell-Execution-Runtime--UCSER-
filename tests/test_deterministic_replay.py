import pytest
import os
import asyncio
from core.ucer import UCER, ExecutionStep
from core.executor import UniversalExecutor
from core.types import Capability, ExecutionContext
from core.db import Database
from tests.harness.replay_engine import ReplayEngine
from unittest.mock import MagicMock

@pytest.mark.asyncio
async def test_deterministic_replay_pass(tmp_path):
    db_path = tmp_path / "replay_pass.db"
    db = Database(str(db_path))
    executor = UniversalExecutor(db=db)
    
    # Mock adapters for determinism
    executor.unified.adapters["bash"] = MagicMock()
    executor.unified.adapters["bash"].run.return_value = {"stdout": "fixed output", "stderr": "", "exit_code": 0}
    
    ucer = UCER(
        intent="Deterministic Test",
        steps=[ExecutionStep(adapter="bash", command="echo 'fixed'")]
    )
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # 1. Execute
    executed_ucer = await executor.execute_ucer(ucer, context=context)
    
    # 2. Replay
    engine = ReplayEngine(executor)
    is_deterministic, drifts = await engine.replay_and_analyze(executed_ucer.command_id)
    
    assert is_deterministic
    assert len(drifts) == 0

@pytest.mark.asyncio
async def test_non_deterministic_drift_detection(tmp_path):
    db_path = tmp_path / "replay_drift.db"
    db = Database(str(db_path))
    executor = UniversalExecutor(db=db)
    
    # Mock adapter to return different values on each call
    mock_adapter = MagicMock()
    mock_adapter.run.side_effect = [
        {"stdout": "output 1", "stderr": "", "exit_code": 0},
        {"stdout": "output 2", "stderr": "", "exit_code": 0}
    ]
    executor.unified.adapters["bash"] = mock_adapter
    
    ucer = UCER(
        intent="Drift Test",
        steps=[ExecutionStep(adapter="bash", command="date")]
    )
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # 1. Execute
    executed_ucer = await executor.execute_ucer(ucer, context=context)
    
    # 2. Replay
    engine = ReplayEngine(executor)
    is_deterministic, drifts = await engine.replay_and_analyze(executed_ucer.command_id)
    
    assert not is_deterministic
    assert len(drifts) == 1
    assert drifts[0]["original"]["stdout"] == "output 1"
    assert drifts[0]["replay"]["stdout"] == "output 2"
