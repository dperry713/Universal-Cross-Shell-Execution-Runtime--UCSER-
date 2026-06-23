import hashlib
import json
from core.ucer import ExecutionTrace

class TraceComparator:
    """
    Compares two ExecutionTraces, ignoring environment-specific noise like timestamps.
    """
    @staticmethod
    def normalize_trace(trace: ExecutionTrace) -> str:
        """
        Strips duration_ms and formats stdout/stderr/exit_code for hashing.
        """
        normalized = {
            "adapter": trace.adapter,
            "command": trace.command.strip(),
            "stdout": trace.stdout.strip(),
            "stderr": trace.stderr.strip(),
            "exit_code": trace.exit_code
        }
        return json.dumps(normalized, sort_keys=True)

    @staticmethod
    def hash_trace(trace: ExecutionTrace) -> str:
        """
        Generates a deterministic hash of the normalized trace.
        """
        data = TraceComparator.normalize_trace(trace).encode('utf-8')
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def assert_equivalent(trace1: ExecutionTrace, trace2: ExecutionTrace) -> bool:
        return TraceComparator.hash_trace(trace1) == TraceComparator.hash_trace(trace2)
