import asyncio

from core.executor import UniversalExecutor
from tests.harness.trace_comparator import TraceComparator


class ReplayEngine:
    """
    High-integrity Replay Engine for UCSER.
    Validates determinism by comparing execution traces bit-for-bit.
    """

    def __init__(self, executor: UniversalExecutor):
        self.executor = executor

    async def replay_and_analyze(self, ucer_id: str) -> tuple[bool, list[dict[str, object]]]:
        """
        Executes a replay and returns a detailed drift analysis.
        """
        original_ucer = await self.executor.db.get_ucer(ucer_id)
        if not original_ucer:
            raise ValueError(f"UCER {ucer_id} not found for replay")

        replay_ucer = await self.executor.replay(ucer_id)

        drifts = []
        is_deterministic = True

        for orig, rep in zip(original_ucer.traces, replay_ucer.traces, strict=False):
            if not TraceComparator.assert_equivalent(orig, rep):
                is_deterministic = False
                drifts.append(
                    {
                        "step_id": orig.step_id,
                        "command": orig.command,
                        "original": {
                            "stdout": orig.stdout,
                            "stderr": orig.stderr,
                            "exit_code": orig.exit_code,
                        },
                        "replay": {
                            "stdout": rep.stdout,
                            "stderr": rep.stderr,
                            "exit_code": rep.exit_code,
                        },
                    }
                )

        return is_deterministic, drifts

    def replay_and_validate(self, ucer_id: str) -> bool:
        is_deterministic, _ = asyncio.run(self.replay_and_analyze(ucer_id))
        return is_deterministic
