from typing import Any

import pytest

from core.db import Database
from core.executor import UniversalExecutor
from tests.harness.deterministic_adapter import DeterministicAdapter


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
    def __init__(self, fixture_map: dict[str, dict[str, Any]] = None):
        self.adapter = DeterministicAdapter(fixture_map)

    def get_powershell(self):
        return self

    def get_bash(self):
        return self

    def sync_cwd(self, cwd, source_session=None):
        pass

    def update_env(self, env, source_session=None):
        pass

    def close_all(self):
        pass


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

        def fake_execute(adapter, command, context):
            return mock_sm.adapter.execute(command)

        executor.unified.execute = fake_execute
        original_execute_ucer = executor.execute_ucer

        def wrapped_execute_ucer(ucer, context=None, allowed_caps=None):
            return original_execute_ucer(ucer, context=context, allowed_caps=allowed_caps)

        executor.execute_ucer = wrapped_execute_ucer
        return executor

    return create_executor
