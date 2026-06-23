import unittest
from semantic.parser import SemanticParser
from core.types import Capability

class TestSemanticExecution(unittest.TestCase):
    def test_pipeline_parsing(self):
        cmd = "ps:Get-Process | Where-Object { $_.Name -match 'python' } | bash:grep 'python'"
        ucer = SemanticParser.parse_raw_pipeline("Find python processes", cmd)
        
        self.assertEqual(len(ucer.execution_steps), 2)
        
        # Step 1: PowerShell
        self.assertEqual(ucer.execution_steps[0].shell, "powershell")
        self.assertTrue(ucer.execution_steps[0].command.startswith("Get-Process"))
        
        # Step 2: Bash
        self.assertEqual(ucer.execution_steps[1].shell, "bash")
        self.assertEqual(ucer.execution_steps[1].command, "grep 'python'")
        
        # Verify Capabilities
        self.assertIn(Capability.EXECUTE_READ, ucer.required_capabilities)
        self.assertIn(Capability.FS_READ, ucer.required_capabilities) # from 'grep' heuristic

    def test_semantic_intent(self):
        ucer = SemanticParser.build_intent_delete("/tmp/malware.sh", is_windows=False)
        
        self.assertEqual(len(ucer.execution_steps), 1)
        self.assertEqual(ucer.execution_steps[0].shell, "bash")
        self.assertIn(Capability.FS_WRITE, ucer.required_capabilities)
        
        # Verify Rollback exists
        self.assertTrue(ucer.rollback_strategy.enabled)
        self.assertEqual(len(ucer.rollback_strategy.steps), 1)

if __name__ == '__main__':
    unittest.main()
