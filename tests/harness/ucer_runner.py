import pytest
from core.executor import UniversalExecutor
from core.db import Database
from tests.harness.deterministic_adapter import DeterministicAdapter
from typing import Dict, Any

class MockSession:
    def __init__(self, adapter: DeterministicAdapter):
        self.adapter = adapter
    
    def execute_stream(self, command: str, timeout: int = None):
        res = self.adapter.execute(command)
        if res.get("stdout"):
            yield {"type": "stdout", "data": res["stdout"]}, None
        if res.get("stderr"):
            yield {"type": "error", "data": res["stderr"]}, None
        # We need to simulate the exit code somehow.
        # Actually, executor.py doesn't pull exit_code from the stream directly right now,
        # it relies on `_drain_stream` returning it, but wait:
        # `_drain_stream` currently returns 0 hardcoded if not changed. Let's patch `_drain_stream` or 
        # simulate the adapter output cleanly.
        pass

# A better approach: patch UniversalExecutor._drain_stream or SessionManager entirely.

class MockSessionManager:
    def __init__(self, fixture_map: Dict[str, Dict[str, Any]] = None):
        self.adapter = DeterministicAdapter(fixture_map)
        
    def get_powershell(self): return self
    def get_bash(self): return self
    def sync_cwd(self, cwd, source_session=None): pass
    def update_env(self, env, source_session=None): pass
    def close_all(self): pass

@pytest.fixture
def memory_db():
    db = Database(db_path=":memory:")
    yield db

@pytest.fixture
def deterministic_executor(memory_db, monkeypatch):
    """
    Returns a UniversalExecutor isolated from the host OS, using DeterministicAdapter.
    """
    def create_executor(fixture_map=None):
        executor = UniversalExecutor(db=memory_db)
        mock_sm = MockSessionManager(fixture_map)
        executor.sessions = mock_sm
        
        def patched_drain_stream(it, session, cmd=None):
            # We override the executor's internal routing to directly use the deterministic adapter
            res = mock_sm.adapter.execute(cmd)
            stdout = res.get("stdout", "").splitlines()
            stderr = res.get("stderr", "").splitlines()
            return res.get("exit_code", 0), stdout, stderr
            
        # We need to monkeypatch the execute_ucer method slightly to pass cmd to patched_drain_stream
        # or we just patch the executor's routing logic.
        original_execute_ucer = executor.execute_ucer
        
        def wrapped_execute_ucer(ucer):
            # Patch the drain_stream method to grab the command from the step
            def drain_hack(it, session):
                # Hack: it's not a generator anymore, we'll pass the command directly
                return patched_drain_stream(None, None, it) # 'it' will be the command string

            executor._drain_stream = drain_hack
            
            # Patch the session execute_stream to just return the command string
            mock_sm.execute_stream = lambda cmd, timeout: cmd
            
            return original_execute_ucer(ucer)
            
        executor.execute_ucer = wrapped_execute_ucer
        return executor
        
    return create_executor
