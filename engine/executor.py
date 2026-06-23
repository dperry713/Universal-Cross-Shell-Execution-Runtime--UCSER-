import subprocess
import time
from engine.schema import ExecutionResult

def run_subprocess(command_id: str, adapter: str, command: str, shell: str, timeout: int = 5) -> ExecutionResult:
    """Centralized execution wrapper to prevent duplicate logic and ensure safety."""
    start = time.time()

    try:
        proc = subprocess.run(
            command,
            shell=True,
            executable=shell,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        result = ExecutionResult(
            command_id=command_id,
            adapter=adapter,
            success=proc.returncode == 0,
            stdout=proc.stdout,
            stderr=proc.stderr,
            exit_code=proc.returncode,
            start_time=start,
            end_time=time.time(),
        )

    except subprocess.TimeoutExpired as e:
        result = ExecutionResult(
            command_id=command_id,
            adapter=adapter,
            success=False,
            stdout=e.stdout or "",
            stderr="TIMEOUT",
            exit_code=-1,
            start_time=start,
            end_time=time.time(),
        )

    result.normalize()
    return result
