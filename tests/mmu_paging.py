import unittest
from core.kernel import get_kernel, SYS_SPAWN, SYS_MMAP
from core.mmu import Page
from core.types import ProcessContext

class TestKernelCore(unittest.TestCase):
    def setUp(self):
        self.kernel = get_kernel()

    def test_spawn_and_mmap(self):
        # 1. Spawn a process via IPC
        pid = self.kernel.ipc.invoke(SYS_SPAWN, None, name="TestShell_1")
        self.assertIn(pid, self.kernel.process_table)
        
        proc = self.kernel.process_table[pid]
        
        # 2. Define a semantic state (e.g., environment variables)
        env_state = {
            "PWD": "/home/user/workspace",
            "USER": "agent_alpha",
            "PATH": "/usr/bin:/bin"
        }
        
        # 3. Map the state into the process's paged memory
        self.kernel.ipc.invoke(SYS_MMAP, proc, state_data=env_state)
        
        # 4. Retrieve the state via the MMU to verify pagination worked
        # We estimate 1 page is enough for this small JSON
        retrieved_state = self.kernel.mmu.retrieve_state(pid, proc.page_directory_base, num_pages=1)
        
        self.assertEqual(retrieved_state["PWD"], "/home/user/workspace")
        self.assertEqual(retrieved_state["USER"], "agent_alpha")
        
        # 5. Verify physical frames were allocated
        self.assertGreater(len(self.kernel.mmu.frames), 0)

if __name__ == '__main__':
    unittest.main()
