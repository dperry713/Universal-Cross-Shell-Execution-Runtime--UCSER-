import pytest

from core.db import Database
from core.executor import UniversalExecutor
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

        def fake_execute(adapter, command, context):
            return mock_sm.adapter.execute(command)

        executor.unified.execute = fake_execute

        original_execute_ucer = executor.execute_ucer

        def wrapped_execute_ucer(ucer, context=None, allowed_caps=None):
            return original_execute_ucer(ucer, context=context, allowed_caps=allowed_caps)

        executor.execute_ucer = wrapped_execute_ucer
        return executor

    return create_executor
