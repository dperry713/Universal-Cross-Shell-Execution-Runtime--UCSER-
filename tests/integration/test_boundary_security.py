import unittest
import os
import uuid
import shutil
from core.ir import SemanticBridge, SecurityError
from core.config import config

class MockExecutor:
    def execute(self, command):
        return [{"type": "text", "data": f"Executed: {command}", "stream": "stdout"}]

class TestBoundarySecurity(unittest.TestCase):
    """
    Phase 4: Integration Testing - Boundary Security Audit
    Adversarial testing of path validation logic.
    """
    def setUp(self):
        self.executor = MockExecutor()
        self.bridge = SemanticBridge(self.executor)
        
        # Setup a clean workspace
        self.old_workspace = config.workspace_base_dir
        self.workspace_name = f"boundary_ws_{uuid.uuid4().hex}"
        # Use a path that is easy to reason about
        config.workspace_base_dir = os.path.abspath(os.path.join(os.getcwd(), self.workspace_name))
        os.makedirs(config.workspace_base_dir, exist_ok=True)

    def tearDown(self):
        config.workspace_base_dir = self.old_workspace
        if os.path.exists(os.path.abspath(self.workspace_name)):
            shutil.rmtree(os.path.abspath(self.workspace_name), ignore_errors=True)

    def test_basic_traversal_blocked(self):
        """Simple ../ traversal attempt."""
        malicious_path = os.path.join(config.workspace_base_dir, "..", "secret.txt")
        with self.assertRaises(SecurityError) as cm:
            self.bridge.delete(malicious_path)
        self.assertIn("Sandbox escape detected", str(cm.exception))

    def test_complex_traversal_blocked(self):
        """Deep traversal attempt with multiple ../."""
        malicious_path = os.path.join(config.workspace_base_dir, "subdir", "..", "..", "..", "windows", "system32", "cmd.exe")
        with self.assertRaises(SecurityError) as cm:
            self.bridge.list_dir(malicious_path)
        self.assertIn("Sandbox escape detected", str(cm.exception))

    def test_absolute_path_escape_blocked(self):
        """Attempting to use an absolute path outside the workspace."""
        # On Windows, this might be another drive or a root folder
        malicious_path = "C:\\Windows\\System32\\drivers\\etc\\hosts"
        if os.name != 'nt':
            malicious_path = "/etc/shadow"
            
        with self.assertRaises(SecurityError) as cm:
            self.bridge.copy(malicious_path, os.path.join(config.workspace_base_dir, "hosts.bak"))
        self.assertIn("Sandbox escape detected", str(cm.exception))

    def test_relative_path_traversal_blocked(self):
        """Relative path that resolves outside workspace."""
        # Change CWD to workspace
        old_cwd = os.getcwd()
        try:
            os.chdir(config.workspace_base_dir)
            malicious_path = "../../sensitive_file"
            with self.assertRaises(SecurityError):
                self.bridge.delete(malicious_path)
        finally:
            os.chdir(old_cwd)

    def test_null_byte_injection_blocked(self):
        """Adversarial path with null byte (if handled by OS)."""
        malicious_path = os.path.join(config.workspace_base_dir, "safe.txt\0/../../etc/passwd")
        # abspath might strip or handle this, but it should still be outside or invalid
        with self.assertRaises(SecurityError):
            self.bridge.delete(malicious_path)

    def test_encoded_traversal_blocked(self):
        """Verify that basic encoding doesn't bypass abspath-based validation."""
        # Note: os.path.abspath handles common normalization, but we check just in case
        malicious_path = os.path.join(config.workspace_base_dir, "foo/./.././../bar")
        with self.assertRaises(SecurityError):
            self.bridge.list_dir(malicious_path)

if __name__ == "__main__":
    unittest.main()
