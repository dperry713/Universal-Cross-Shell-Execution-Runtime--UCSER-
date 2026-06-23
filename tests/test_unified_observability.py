import pytest
import asyncio
from utils.observability.metrics import metrics, TelemetryProvider
from utils.observability.tracing import Tracer, Span

@pytest.mark.asyncio
async def test_metrics_collection():
    metrics.reset()
    # Reset or use fresh name
    test_adapter = "test_shell"
    
    provider = TelemetryProvider()
    await provider.emit_execution_metric("job-1", test_adapter, 150.5, True)
    await provider.emit_execution_metric("job-2", test_adapter, 250.5, False)
    
    snapshot = metrics.get_snapshot()
    
    assert snapshot["counts"][f"exec.count.{test_adapter}"] == 2
    assert snapshot["counts"]["exec.success"] == 1
    assert snapshot["counts"]["exec.failure"] == 1
    
    latency = snapshot["latencies"][f"exec.latency.{test_adapter}"]
    assert latency["avg"] == 200.5
    assert latency["max"] == 250.5
    assert latency["count"] == 2

def test_distributed_tracing_propagation():
    trace_id = Tracer.start_trace("manual-trace-id")
    assert Tracer.get_current_trace_id() == "manual-trace-id"
    
    with Span("test-span") as span:
        assert span.trace_id == "manual-trace-id"
        assert span.start_time is not None
        
    Tracer.clear_trace()
    assert Tracer.get_current_trace_id() is None

@pytest.mark.asyncio
async def test_executor_telemetry_integration(tmp_path):
    from core.executor import UniversalExecutor
    from core.ucer import UCER, ExecutionStep
    from core.types import ExecutionContext, Capability
    from core.db import Database
    from unittest.mock import MagicMock
    
    db_path = tmp_path / "telemetry.db"
    db = Database(str(db_path))
    executor = UniversalExecutor(db=db)
    
    # Mock adapter
    mock_adapter = MagicMock()
    mock_adapter.run.return_value = {"stdout": "ok", "stderr": "", "exit_code": 0}
    executor.unified.adapters["bash"] = mock_adapter
    
    ucer = UCER(intent="telemetry test", steps=[ExecutionStep(adapter="bash", command="test")])
    context = ExecutionContext(capabilities={Capability.EXEC})
    
    # Run execution
    await executor.execute_ucer(ucer, context=context)
    
    # Give background tasks a moment to run if any
    await asyncio.sleep(0.05)
    
    snapshot = metrics.get_snapshot()
    assert snapshot["counts"]["exec.count.bash"] >= 1
    assert ucer.traces[0].duration_ms > 0
