import pytest
import os
import asyncio
from core.db import Database
from core.ucer import UCER, ExecutionStep, ExecutionTrace
from core.types import Capability

@pytest.mark.asyncio
async def test_database_ucer_persistence(tmp_path):
    db_path = tmp_path / "persistence.db"
    db = Database(str(db_path))
    
    # 1. Create a UCER with traces
    ucer = UCER(
        intent="Persistence Test",
        steps=[ExecutionStep(adapter="bash", command="whoami")],
        status="completed"
    )
    ucer.traces.append(ExecutionTrace(
        step_id="step-1",
        adapter="bash",
        command="whoami",
        stdout="root",
        stderr="",
        exit_code=0,
        duration_ms=10.5
    ))
    
    # 2. Save
    await db.save_ucer(ucer)
    
    # 3. Retrieve and Verify
    retrieved = await db.get_ucer(ucer.command_id)
    assert retrieved is not None
    assert retrieved.intent == "Persistence Test"
    assert len(retrieved.traces) == 1
    assert retrieved.traces[0].stdout == "root"
    assert retrieved.status == "completed"

@pytest.mark.asyncio
async def test_database_kv_store(tmp_path):
    db_path = tmp_path / "kv.db"
    db = Database(str(db_path))
    
    # Set and Get complex object
    config_state = {"nodes": ["node-1", "node-2"], "active": True}
    await db.set_kv("system.config", config_state)
    
    retrieved = await db.get_kv("system.config")
    assert retrieved == config_state
    assert retrieved["active"] is True

@pytest.mark.asyncio
async def test_database_atomic_trace_replacement(tmp_path):
    db_path = tmp_path / "atomic.db"
    db = Database(str(db_path))
    
    ucer = UCER(intent="Atomic Test", steps=[])
    ucer.traces.append(ExecutionTrace(
        step_id="id1", adapter="bash", command="cmd1", stdout="out1", stderr="", exit_code=0, duration_ms=0
    ))
    await db.save_ucer(ucer)
    
    # Update UCER with NEW trace list (should replace old one)
    ucer.traces = [ExecutionTrace(
        step_id="id2", adapter="bash", command="cmd2", stdout="out2", stderr="", exit_code=0, duration_ms=0
    )]
    await db.save_ucer(ucer)
    
    retrieved = await db.get_ucer(ucer.command_id)
    assert len(retrieved.traces) == 1
    assert retrieved.traces[0].step_id == "id2"
