from typing import Dict, List, Any
import logging
import os
from engine.adapters.powershell import PowerShellAdapter
from engine.adapters.bash import BashAdapter
from engine.adapters.python import PythonAdapter
from engine.schema import ExecutionResult
from engine.state_manager import StateSnapshot

from core.types import ExecutionContext, Capability
from security.contract import FormalContract

logger = logging.getLogger("Kernel.ExecutionManager")

class ExecutionManager:
    """Core Orchestrator for executing the UCER schema with transactional integrity."""
    
    def __init__(self, working_dir: str = "./runtime_space"):
        self.working_dir = working_dir
        if not os.path.exists(self.working_dir):
            os.makedirs(self.working_dir)
            
        self.adapters = {
            "powershell": PowerShellAdapter(),
            "bash": BashAdapter(),
            "python": PythonAdapter(),
        }

    @FormalContract.requires({Capability.EXEC})
    def execute_ucer(self, ucer: Dict[str, Any], context: ExecutionContext) -> List[ExecutionResult]:
        results = []
        command_id = ucer.get("command_id")
        steps = ucer.get("steps", [])

        # Transactional Initialization: Capture snapshot before pipeline starts
        snapshot = StateSnapshot(self.working_dir)
        snapshot.capture_backup()

        try:
            for step in steps:
                adapter_name = step.get("adapter")
                command = step.get("command")

                adapter = self.adapters.get(adapter_name)
                if not adapter:
                    raise ValueError(f"Unsupported adapter: {adapter_name}")

                # Execute with environment routing to working_dir
                result = adapter.execute(command_id, command, cwd=self.working_dir)
                results.append(result)

                if not result.success:
                    logger.warning(f"Pipeline failure at step {step.get('step_id')}. Triggering Rollback.")
                    snapshot.restore()
                    break
            
            # If all successful, cleanup backup
            if all(r.success for r in results):
                snapshot.cleanup()

        except Exception as e:
            logger.error(f"Execution Engine Fault: {e}. Reverting state.")
            snapshot.restore()
            raise

        return results
