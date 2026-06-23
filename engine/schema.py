from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time
import hashlib

@dataclass
class ExecutionResult:
    command_id: str
    adapter: str
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    start_time: float
    end_time: float
    duration_ms: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def normalize(self):
        """Ensures cross-platform string parity."""
        self.stdout = self.stdout.strip().replace("\r\n", "\n")
        self.stderr = self.stderr.strip().replace("\r\n", "\n")
        self.duration_ms = int((self.end_time - self.start_time) * 1000)

    def deterministic_hash(self) -> str:
        """Cryptographic proof of execution output."""
        payload = f"{self.command_id}{self.adapter}{self.stdout}{self.stderr}{self.exit_code}"
        return hashlib.sha256(payload.encode()).hexdigest()
