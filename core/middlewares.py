import asyncio
import time

from core.executor import SecurityError
from core.pipeline import BaseMiddleware
from core.types import ExecutionContext
from core.ucer import UCER, ExecutionTrace
from utils.cryptography import generate_key_pair


class CryptoMiddleware(BaseMiddleware):
    """Phase 4 & 5: Verifies intent signature and generates Ephemeral Keys."""

    def __init__(self, cp_pub_path: str, cp_priv_key: bytes):
        super().__init__()
        self.cp_pub_path = cp_pub_path
        self.cp_priv_key = cp_priv_key

    async def process(self, ucer: UCER, context: ExecutionContext) -> UCER:
        cp_pub_key = await asyncio.to_thread(self._read_pub_key)

        if ucer.control_signature:
            if not ucer.verify_integrity(cp_pub_key):
                ucer.status = "failed"
                raise SecurityError("UCER Integrity Check Failed: Intent has been tampered with.")
        else:
            ucer.sign_intent(self.cp_priv_key)

        exec_priv, exec_pub = generate_key_pair()
        ucer.execution_pub_key = (
            exec_pub.decode("utf-8") if isinstance(exec_pub, bytes) else exec_pub
        )

        return await super().process(ucer, context)

    def _read_pub_key(self) -> bytes:
        with open(self.cp_pub_path, "rb") as f:
            return f.read()


class PolicyMiddleware(BaseMiddleware):
    """Phase 4 Enforcement: Evaluates UCER against PolicyGate."""

    def __init__(self, policy_gate):
        super().__init__()
        self.policy_gate = policy_gate

    async def process(self, ucer: UCER, context: ExecutionContext) -> UCER:
        self.policy_gate.evaluate(ucer, context)
        return await super().process(ucer, context)


class PersistenceMiddleware(BaseMiddleware):
    """Saves state to DB before and after execution."""

    def __init__(self, db):
        super().__init__()
        self.db = db

    async def process(self, ucer: UCER, context: ExecutionContext) -> UCER:
        ucer.status = "running"
        ucer.traces = []
        await self.db.save_ucer(ucer)

        try:
            ucer = await super().process(ucer, context)
            ucer.status = "completed" if ucer.status != "failed" else "failed"
        except Exception:
            ucer.status = "failed"
            raise
        finally:
            await self.db.save_ucer(ucer)

        return ucer


class EngineMiddleware(BaseMiddleware):
    """Executes the UCER steps via UnifiedExecutor with Sentinel monitoring and Telemetry."""

    def __init__(self, unified, sentinel, telemetry, node_manager):
        super().__init__()
        self.unified = unified
        self.sentinel = sentinel
        self.telemetry = telemetry
        self.node_manager = node_manager

    async def process(self, ucer: UCER, context: ExecutionContext) -> UCER:
        from core.executor import normalize_output
        from utils.observability.tracing import Span, Tracer

        isolation_level = self.node_manager.negotiate_isolation(ucer)
        Tracer.start_trace(ucer.command_id)

        try:
            for step in ucer.steps:
                adapter_name = step.adapter.lower()
                if isolation_level == "microvm":
                    adapter_name = "microvm"

                step_start = time.perf_counter()

                try:
                    with Span(f"exec_step_{step.step_id}", {"adapter": adapter_name}):
                        # Execute is sync in adapters, wrap in thread to prevent blocking the async loop
                        result = await asyncio.to_thread(
                            self.unified.execute, adapter_name, step.command, context
                        )

                    duration_ms = (time.perf_counter() - step_start) * 1000

                    trace = ExecutionTrace(
                        step_id=step.step_id,
                        adapter=adapter_name,
                        command=step.command,
                        stdout=normalize_output(result.get("stdout", "")),
                        stderr=normalize_output(result.get("stderr", "")),
                        exit_code=result.get("exit_code", -1),
                        side_effects=result.get("side_effects", {}),
                        duration_ms=duration_ms,
                    )

                    if not self.sentinel.inspect_trace(trace, context):
                        ucer.status = "failed"
                        raise SecurityError(
                            f"Sentinel Blocked Execution at step {step.step_id}: Behavioral Anomaly Detected."
                        )

                    ucer.traces.append(trace)
                    if trace.exit_code != 0:
                        ucer.status = "failed"
                        break
                    asyncio.create_task(
                        self.telemetry.emit_execution_metric(
                            ucer.command_id, adapter_name, duration_ms, True
                        )
                    )

                except Exception:
                    ucer.status = "failed"
                    asyncio.create_task(
                        self.telemetry.emit_execution_metric(
                            ucer.command_id, adapter_name, 0.0, False
                        )
                    )
                    raise

            return ucer
        finally:
            Tracer.clear_trace()
