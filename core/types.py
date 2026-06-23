from dataclasses import dataclass, field
from typing import Dict, Any, Set
import uuid
import time
from enum import Enum

class Capability(str, Enum):
    DELETE_ROOT = "delete_root"
    WRITE_FS = "write_fs"
    NETWORK = "network"
    EXEC = "exec"
    FS_READ = "fs_read"
    ENV_MUTATE = "env_mutate"
    EXECUTE_READ = "execute_read"

@dataclass
class ExecutionContext:
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str = "default"
    environment: Dict[str, str] = field(default_factory=dict)
    working_dir: str = "/tmp"
    created_at: float = field(default_factory=time.time)
    capabilities: Set[Capability] = field(default_factory=set)

    def snapshot(self):
        return {
            "execution_id": self.execution_id,
            "env": dict(self.environment),
            "cwd": self.working_dir,
            "capabilities": [cap.value for cap in self.capabilities],
            "timestamp": self.created_at
        }
