import pytest
import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
from core.scheduler import JobScheduler, DistributedWorker
from core.ucer import UCER, ExecutionStep
from core.types import ExecutionContext

@pytest.mark.asyncio
async def test_job_submission_logic():
    # Mock NATS and JetStream
    mock_nc = AsyncMock()
    mock_js = AsyncMock()
    
    scheduler = JobScheduler()
    scheduler.nc = mock_nc
    scheduler.js = mock_js
    
    ucer = UCER(intent="test", steps=[ExecutionStep(adapter="bash", command="whoami")])
    context = ExecutionContext()
    
    # Mock the publish response
    mock_ack = MagicMock()
    mock_ack.stream = "UCSER_JOBS"
    mock_ack.seq = 1
    mock_js.publish.return_value = mock_ack
    
    seq = await scheduler.submit_job(ucer, context)
    
    assert seq == 1
    mock_js.publish.assert_called_once()
    # Verify subject format
    args, kwargs = mock_js.publish.call_args
    assert args[0].startswith("ucser.jobs.")

@pytest.mark.asyncio
async def test_worker_processing_loop():
    mock_nc = AsyncMock()
    mock_js = AsyncMock()
    mock_sub = AsyncMock()
    
    worker = DistributedWorker(worker_id="test-worker")
    worker.nc = mock_nc
    worker.js = mock_js
    
    # Mock message
    mock_msg = AsyncMock()
    mock_msg.data = json.dumps({
        "ucer": {"command_id": "test-id", "intent": "test", "steps": []},
        "context": {}
    }).encode()
    
    # next_msg side_effect: return one message then wait forever
    async def next_msg_side_effect(timeout=None):
        if next_msg_side_effect.called:
            await asyncio.Future() # Wait forever
        next_msg_side_effect.called = True
        return mock_msg
    
    next_msg_side_effect.called = False
    mock_sub.next_msg.side_effect = next_msg_side_effect
    mock_js.subscribe.return_value = mock_sub
    
    callback = AsyncMock()
    
    # Run the worker start and cancel after processing
    task = asyncio.create_task(worker.start(callback))
    # Wait for the callback to be called
    for _ in range(10):
        if callback.called: break
        await asyncio.sleep(0.01)
        
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    callback.assert_called_once()
    mock_msg.ack.assert_called_once()
