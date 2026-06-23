import unittest
from security.policy import PolicyEngine
from core.types import Capability
from core.dsl import WriteFileIntent, NetworkRequestIntent

class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.engine = PolicyEngine()

    def test_map_capabilities_from_dsl(self):
        intents = [
            WriteFileIntent(intent="write_file", path="test.txt", content="hi"),
            NetworkRequestIntent(intent="network_request", url="http://example.com")
        ]
        caps = self.engine.map_capabilities_from_dsl(intents)
        self.assertIn(Capability.WRITE_FS, caps)
        self.assertIn(Capability.NETWORK, caps)

    def test_map_capabilities_ast(self):
        # Mock AST-like object
        class MockNode:
            def __init__(self, command):
                self.command = command
        class MockAST:
            def __init__(self, nodes):
                self.nodes = nodes
        
        ast = MockAST([MockNode("Remove-Item"), MockNode("curl")])
        caps = self.engine.map_capabilities(ast, "powershell")
        self.assertIn(Capability.WRITE_FS, caps)
        self.assertIn(Capability.NETWORK, caps)

    def test_is_allowed(self):
        allowed = {Capability.FS_READ, Capability.EXEC}
        requested = {Capability.FS_READ}
        self.assertTrue(self.engine.is_allowed(requested, allowed))
        
        requested_forbidden = {Capability.WRITE_FS}
        self.assertFalse(self.engine.is_allowed(requested_forbidden, allowed))

if __name__ == '__main__':
    unittest.main()
