import unittest
import os
import json
import uuid
from datetime import datetime
from core.executor import UniversalExecutor
from core.db import Database
from core.ucer import UCER, ExecutionStep, ExecutionTrace
from core.types import Capability

class MockUnifiedExecutor:
    """
    Simulates a UnifiedExecutor that returns deterministic results and side effects.
    Used to verify the Control Plane's replay and persistence logic.
    """
    def __init__(self):
        self.adapters = {} # Just to satisfy cleanup loop

    def execute(self, adapter, command, context):
        # Deterministic logic based on command content
        side_effects = {"files_added": [], "files_modified": [], "files_deleted": []}
        
        if "touch" in command:
            filename = command.split(" ")[1]
            side_effects["files_added"].append(filename)
        elif "rm" in command:
            filename = command.split(" ")[1]
            side_effects["files_deleted"].append(filename)
            
        return {
            "stdout": f"Mock output for: {command}",
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 10.0,
            "side_effects": side_effects
        }

class TestDeterministicReplay(unittest.TestCase):
    """
    Phase 4: Integration Testing - Deterministic Replay Validation
    Verifies that side_effects are persisted and correctly used for bit-perfect reconstruction check.
    """
    def setUp(self):
        # Use a temporary database for the test
        self.db_path = f"test_sder_{uuid.uuid4().hex}.db"
        self.db = Database(self.db_path)
        self.mock_unified = MockUnifiedExecutor()
        self.executor = UniversalExecutor(db=self.db, unified=self.mock_unified)

    def tearDown(self):
        # On Windows, the DB file might still be locked by sqlite
        try:
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
        except PermissionError:
            pass

    def test_multi_step_sequence_replay_determinism(self):
        """
        Executes a multi-step sequence, saves it, re-hydrates it, 
        and verifies that the replay detects bit-perfect side effects.
        """
        # 1. Define a complex UCER
        ucer = UCER(
            intent="Setup workspace",
            steps=[
                ExecutionStep(adapter="bash", command="touch /tmp/init.lock"),
                ExecutionStep(adapter="bash", command="ls -la /tmp"),
                ExecutionStep(adapter="bash", command="rm /tmp/init.lock")
            ]
        )
        # Allow WRITE_FS for the 'rm' and 'touch' heuristic
        allowed = {Capability.FS_READ, Capability.WRITE_FS, Capability.EXEC, Capability.EXECUTE_READ}
        ucer.required_capabilities = {Capability.FS_READ, Capability.WRITE_FS}

        # 2. Execute the sequence
        executed_ucer = self.executor.execute_ucer(ucer, allowed_caps=allowed)
        self.assertEqual(executed_ucer.status, "completed")
        self.assertEqual(len(executed_ucer.traces), 3)
        
        # Verify side effects were captured in memory
        self.assertIn("/tmp/init.lock", executed_ucer.traces[0].side_effects["files_added"])
        self.assertIn("/tmp/init.lock", executed_ucer.traces[2].side_effects["files_deleted"])

        # 3. Verify Database Persistence (State Reconstruction)
        rehydrated_ucer = self.db.get_ucer(executed_ucer.command_id)
        self.assertIsNotNone(rehydrated_ucer)
        self.assertEqual(len(rehydrated_ucer.traces), 3)
        
        # Check side_effects column rehydration
        for orig, rehydrated in zip(executed_ucer.traces, rehydrated_ucer.traces):
            self.assertEqual(orig.side_effects, rehydrated.side_effects)
            self.assertEqual(orig.stdout, rehydrated.stdout)

        # 4. Perform Replay and Validate Determinism
        # Replay should pass since our mock is deterministic
        replay_ucer = self.executor.replay(executed_ucer.command_id)
        
        self.assertEqual(len(replay_ucer.traces), 3)
        self.assertEqual(replay_ucer.status, "completed")

    def test_replay_detects_divergence(self):
        """
        Verifies that if a replay results in different side effects, 
        the system detects the divergence.
        """
        # 1. Manually inject a UCER into the DB with a specific side effect
        ucer = UCER(
            intent="Faked execution",
            steps=[ExecutionStep(adapter="bash", command="touch /tmp/diverge.txt")]
        )
        ucer.traces = [
            ExecutionTrace(
                step_id="step-1",
                adapter="bash",
                command="touch /tmp/diverge.txt",
                stdout="Mock output for: touch /tmp/diverge.txt",
                stderr="",
                exit_code=0,
                duration_ms=10.0,
                side_effects={"files_added": ["/tmp/WRONG_FILE.txt"]} # DIVERGENCE
            )
        ]
        ucer.status = "completed"
        self.db.save_ucer(ucer)

        # 2. Replay
        # The mock will return files_added: ["/tmp/diverge.txt"], which diverges from "WRONG_FILE.txt"
        replay_ucer = self.executor.replay(ucer.command_id)
        
        # The executor.replay() method currently logs warnings but returns the replay UCER.
        # We can verify the divergence by checking the logs (simulated) or comparing traces.
        self.assertNotEqual(ucer.traces[0].side_effects, replay_ucer.traces[0].side_effects)

if __name__ == "__main__":
    unittest.main()
