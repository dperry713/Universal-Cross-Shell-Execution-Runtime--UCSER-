import unittest
import os
import threading
import base64
import uuid
import shutil
import time
import re
from core.ir import SemanticBridge, SecurityError
from core.config import config

class MockStreamingExecutor:
    """
    Simulates a shell executor that handles streamed base64 chunks.
    """
    def __init__(self):
        self.received_data = {} # path -> bytes
        self.lock = threading.Lock()

    def execute(self, command):
        # Simulate WINDOWS -> LINUX (W->L)
        if "base64 -di" in command:
            lines = command.splitlines()
            match = re.search(r">> '(.*)'", lines[0])
            if not match: return []
            dest = match.group(1)
            b64_data = "".join(lines[1:-1]).strip()
            chunk = base64.b64decode(b64_data)
            with self.lock:
                if dest not in self.received_data:
                    self.received_data[dest] = b""
                self.received_data[dest] += chunk
            return [{"type": "text", "data": "Chunk received", "stream": "stdout"}]
        return []

class TestBridgeStress(unittest.TestCase):
    def setUp(self):
        self.executor = MockStreamingExecutor()
        self.bridge = SemanticBridge(self.executor)
        
        # WEIRD HACK for Windows testing of cross-OS logic:
        # We need a path that starts with '/' to be 'LINUX' but passes os.path.abspath check.
        # We'll override config.workspace_base_dir to a root-relative path.
        self.old_workspace = config.workspace_base_dir
        
        # On Windows, os.path.abspath('/ucser_test_ws') -> 'C:\ucser_test_ws'
        config.workspace_base_dir = '/ucser_test_ws'
        self.test_dir = os.path.abspath(config.workspace_base_dir)
        os.makedirs(self.test_dir, exist_ok=True)

    def tearDown(self):
        config.workspace_base_dir = self.old_workspace
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_large_file_integrity_win_to_linux(self):
        """Verify that a multi-megabyte file is correctly chunked and reconstructed."""
        # Source is a host file (WINDOWS OS)
        file_path = os.path.join(self.test_dir, "large_host.bin")
        original_data = os.urandom(1024 * 1024)
        with open(file_path, "wb") as f:
            f.write(original_data)
        
        # Dest starts with '/' (LINUX OS)
        dest_path = "/ucser_test_ws/guest_large.bin"
        
        self.bridge.copy(file_path, dest_path)
        
        received = self.executor.received_data.get(dest_path)
        self.assertIsNotNone(received, "No data received in mock executor")
        self.assertEqual(len(received), len(original_data))
        self.assertEqual(received, original_data)

    def test_concurrent_transfers(self):
        """Verify that multiple simultaneous transfers do not corrupt each other."""
        num_threads = 10
        file_size = 128 * 1024
        
        threads = []
        errors = []

        def worker(thread_id):
            try:
                src = os.path.join(self.test_dir, f"src_{thread_id}.bin")
                data = os.urandom(file_size)
                with open(src, "wb") as f:
                    f.write(data)
                
                dst = f"/ucser_test_ws/dst_{thread_id}.bin"
                self.bridge.copy(src, dst)
                
                received = self.executor.received_data.get(dst)
                if received != data:
                    errors.append(f"Data corruption in thread {thread_id}")
            except Exception as e:
                errors.append(f"Exception in thread {thread_id}: {str(e)}")

        for i in range(num_threads):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Errors detected: {errors}")

if __name__ == "__main__":
    unittest.main()
