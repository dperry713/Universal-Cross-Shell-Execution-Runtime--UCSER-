import asyncio
import copy
import os
import re

from core.config import config
from core.db import Database, DatabaseBase
from core.distributed import DistributedNodeManager
from core.microvm import MicroVMExecutor
from core.sandbox import SandboxExecutor
from core.types import Capability, ExecutionContext
from core.ucer import UCER, ExecutionTrace
from core.unified_executor import UnifiedExecutor
from security.auditor import BashASTAuditor
from security.policy import PolicyGate
from security.ps_daemon import PersistentPowerShellAuditor
from security.sentinel import SecuritySentinel
from utils.cryptography import generate_key_pair
from utils.observability.logging import get_logger
from utils.observability.metrics import TelemetryProvider

logger = get_logger(__name__, level=config.log_level)


class SecurityError(Exception):
    pass


def normalize_output(text: str) -> str:
    """Removes non-deterministic noise from stdout (ANSI colors, trailing whitespace)."""
    ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    text = ansi_escape.sub("", text)
    return text.strip()


class UniversalExecutorFacade:
    """
    Wraps the UnifiedExecutor to maintain compatibility with the existing UCSER CLI and Database.
    Implements the Ephemeral Signing Trust Chain, Security Sentinel monitoring, Unified Telemetry,
    and Advanced Isolation Negotiation.
    """

    def __init__(self, db: DatabaseBase | None = None, unified: UnifiedExecutor | None = None):
        self.db = db or Database()
        self.policy_gate = PolicyGate()
        self.sentinel = SecuritySentinel()
        self.telemetry = TelemetryProvider()
        self.node_manager = DistributedNodeManager()

        self.cp_priv_path = config.cp_private_key_path
        self.cp_pub_path = config.cp_public_key_path
        if not os.path.exists(self.cp_priv_path):
            logger.info("Generating new Control Plane key pair")
            os.makedirs(os.path.dirname(os.path.abspath(self.cp_priv_path)), exist_ok=True)
            os.makedirs(os.path.dirname(os.path.abspath(self.cp_pub_path)), exist_ok=True)
            priv, pub = generate_key_pair()
            with open(self.cp_priv_path, "wb") as f:
                f.write(priv)
            with open(self.cp_pub_path, "wb") as f:
                f.write(pub)

        with open(self.cp_priv_path, "rb") as f:
            self.control_plane_private_key = f.read()

        if unified:
            self.unified = unified
        else:
            auditors = {
                "powershell": PersistentPowerShellAuditor(),
                "ps": PersistentPowerShellAuditor(),
                "bash": BashASTAuditor(),
                "linux": BashASTAuditor(),
                "microvm": BashASTAuditor(),
            }

            adapters = {
                "powershell": SandboxExecutor("powershell"),
                "ps": SandboxExecutor("ps"),
                "bash": SandboxExecutor("bash"),
                "linux": SandboxExecutor("linux"),
                "microvm": MicroVMExecutor("bash"),
            }

            self.unified = UnifiedExecutor(auditors, self.policy_gate, adapters)

        # Build the Async Pipeline
        from core.middlewares import (
            CryptoMiddleware,
            EngineMiddleware,
            PersistenceMiddleware,
            PolicyMiddleware,
        )
        from core.pipeline import PipelineBuilder

        builder = PipelineBuilder()
        builder.add(CryptoMiddleware(self.cp_pub_path, self.control_plane_private_key))
        builder.add(PolicyMiddleware(self.policy_gate))
        builder.add(PersistenceMiddleware(self.db))
        builder.add(
            EngineMiddleware(self.unified, self.sentinel, self.telemetry, self.node_manager)
        )
        self._pipeline_process = builder.build()

    def execute(self, command: str):
        """
        Synchronous wrapper around the async execute_ucer for compatibility with CLI/scripts.
        Yields traces as they become available (simulated streaming from the result).
        """
        from core.types import Capability, ExecutionContext
        from core.ucer import UCER, ExecutionStep

        # Parse shell prefix if present (e.g., 'ps:ls')
        shell = "bash"
        cmd = command
        if ":" in command:
            parts = command.split(":", 1)
            if parts[0] in ["ps", "powershell", "bash"]:
                shell = parts[0]
                cmd = parts[1]

        ucer = UCER(intent="synchronous_exec", steps=[ExecutionStep(adapter=shell, command=cmd)])
        context = ExecutionContext(capabilities={Capability.EXEC})

        result = self.execute_ucer(ucer, context)
        if asyncio.iscoroutine(result):
            loop = None
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            result = loop.run_until_complete(result)

        for trace in result.traces:
            if trace.stdout:
                yield {"stream": "stdout", "data": trace.stdout}
            if trace.stderr:
                yield {"stream": "stderr", "data": trace.stderr}

    def close(self):
        """Cleanup resources."""
        pass

    def _run_or_return(self, coro):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        return coro

    def execute_ucer(
        self,
        ucer: UCER,
        context: ExecutionContext | None = None,
        allowed_caps: set[Capability] | None = None,
    ):
        """
        Executes a UCER through the async Middleware Pipeline.
        Returns a UCER directly in synchronous contexts and a coroutine in async contexts.
        """

        async def _execute():
            active_context = context or ExecutionContext(
                capabilities={Capability.EXEC, Capability.FS_READ}
            )
            # If allowed_caps is provided, we temporarily attach it to the context for the PolicyMiddleware
            # This is a bit of a hack for backwards compatibility with the sync API signature.
            if allowed_caps is not None:
                active_context = copy.deepcopy(active_context)
                active_context.capabilities = allowed_caps
            return await self._pipeline_process(ucer, active_context)

        return self._run_or_return(_execute())

    def replay(self, ucer_id: str, context: ExecutionContext | None = None):
        """
        Replays a UCER to verify bit-for-bit parity.
        Returns a UCER directly in synchronous contexts and a coroutine in async contexts.
        """

        async def _replay():
            original = await self.db.get_ucer(ucer_id)
            if not original:
                raise ValueError(f"UCER {ucer_id} not found for replay")

            logger.info(f"Initiating replay for UCER {ucer_id}")

            from engine.state_manager import StateSnapshot

            snapshot = StateSnapshot(config.workspace_base_dir)
            snapshot.capture_backup()

            replay_caps = original.required_capabilities.copy()
            if not replay_caps:
                replay_caps.add(Capability.EXEC)

            active_context = context or ExecutionContext(
                execution_id=f"replay-{original.command_id}", capabilities=replay_caps
            )

            isolation_level = self.node_manager.negotiate_isolation(original)

            replay_ucer = original.model_copy(deep=True)
            replay_ucer.traces = []
            replay_ucer.status = "running"

            try:
                for step in replay_ucer.steps:
                    adapter_name = step.adapter.lower()
                    if isolation_level == "microvm":
                        adapter_name = "microvm"

                    # Execute is sync in adapters, wrap in thread to prevent blocking
                    result = await asyncio.to_thread(
                        self.unified.execute, adapter_name, step.command, active_context
                    )
                    trace = ExecutionTrace(
                        step_id=step.step_id,
                        adapter=adapter_name,
                        command=step.command,
                        stdout=normalize_output(result.get("stdout", "")),
                        stderr=normalize_output(result.get("stderr", "")),
                        exit_code=result.get("exit_code", -1),
                        duration_ms=result.get("duration_ms", 0.0),
                    )
                    replay_ucer.traces.append(trace)

                replay_ucer.status = "completed"
                return replay_ucer
            finally:
                logger.info("Replay finished. Rolling back state to pre-replay snapshot.")
                snapshot.restore()

        return self._run_or_return(_replay())


class UniversalExecutor(UniversalExecutorFacade):
    pass
