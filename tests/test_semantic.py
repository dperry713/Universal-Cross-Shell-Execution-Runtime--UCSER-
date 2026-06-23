import unittest
from semantic.parser import SemanticParser
from core.types import Capability

class TestSemanticParser(unittest.TestCase):
    def test_determine_shell(self):
        self.assertEqual(SemanticParser._determine_shell("ps:Get-Date"), "powershell")
        self.assertEqual(SemanticParser._determine_shell("bash:ls"), "bash")
        self.assertEqual(SemanticParser._determine_shell("python:print('hi')"), "python")
        self.assertEqual(SemanticParser._determine_shell("Get-Process"), "powershell")
        self.assertEqual(SemanticParser._determine_shell("echo hello"), "bash")

    def test_parse_raw_pipeline(self):
        ucer = SemanticParser.parse_raw_pipeline("Test Pipeline", "ps:Get-Process | bash:grep python")
        self.assertEqual(len(ucer.execution_steps), 2)
        self.assertEqual(ucer.execution_steps[0].shell, "powershell")
        self.assertEqual(ucer.execution_steps[0].command, "Get-Process")
        self.assertEqual(ucer.execution_steps[1].shell, "bash")
        self.assertEqual(ucer.execution_steps[1].command, "grep python")
        
    def test_capability_aggregation(self):
        # cat (READ) + rm (WRITE)
        ucer = SemanticParser.parse_raw_pipeline("Agg Test", "bash:cat file.txt | bash:rm file.txt")
        caps = set(ucer.required_capabilities)
        self.assertIn(Capability.FS_READ, caps)
        self.assertIn(Capability.WRITE_FS, caps)

    def test_build_intent_delete_windows(self):
        ucer = SemanticParser.build_intent_delete("C:\\test.txt", is_windows=True)
        self.assertEqual(ucer.execution_steps[0].shell, "powershell")
        self.assertIn("Remove-Item", ucer.execution_steps[0].command)
        self.assertTrue(ucer.rollback_strategy.enabled)
        self.assertIn("Copy-Item", ucer.rollback_strategy.steps[0].command)

    def test_build_intent_delete_linux(self):
        ucer = SemanticParser.build_intent_delete("/tmp/test.txt", is_windows=False)
        self.assertEqual(ucer.execution_steps[0].shell, "bash")
        self.assertIn("rm -rf", ucer.execution_steps[0].command)
        self.assertTrue(ucer.rollback_strategy.enabled)
        self.assertIn("cp -r", ucer.rollback_strategy.steps[0].command)

if __name__ == '__main__':
    unittest.main()
