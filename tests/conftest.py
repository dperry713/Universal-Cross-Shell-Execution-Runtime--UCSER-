import pytest
from core.executor import UniversalExecutor
from core.db import Database
from tests.harness.ucer_runner import MockSessionManager

@pytest.fixture
def memory_db(tmp_path):
    # Use a real file in a tmp dir to avoid the sqlite :memory: multiple connection issue
    db_file = tmp_path / "test.db"
    db = Database(db_path=str(db_file))
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
            
        original_execute_ucer = executor.execute_ucer
        
        def wrapped_execute_ucer(ucer):
            def drain_hack(it, session):
                return patched_drain_stream(None, None, it)

            executor._drain_stream = drain_hack
            mock_sm.execute_stream = lambda cmd, timeout: cmd
            return original_execute_ucer(ucer)
            
        executor.execute_ucer = wrapped_execute_ucer
        return executor
        
    return create_executor
