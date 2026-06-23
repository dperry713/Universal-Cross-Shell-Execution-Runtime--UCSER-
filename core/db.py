import asyncio
import json
import os
import sqlite3
from datetime import datetime
from typing import Any

from core.config import config
from core.ucer import UCER
from utils.observability.logging import get_logger

logger = get_logger(__name__, level=config.log_level)


class DatabaseBase:
    async def connect(self):
        pass

    async def close(self):
        pass

    async def save_ucer(self, ucer: UCER):
        raise NotImplementedError

    async def get_ucer(self, command_id: str) -> UCER | None:
        raise NotImplementedError

    async def list_ucers(self, limit: int = 50) -> list[UCER]:
        raise NotImplementedError

    async def set_kv(self, key: str, value: Any):
        raise NotImplementedError

    async def get_kv(self, key: str) -> Any | None:
        raise NotImplementedError


class SQLiteDatabase(DatabaseBase):
    """Legacy local SQLite state storage. Used for standalone/local tests."""

    def __init__(self, db_path: str | None = None):
        self.db_path = db_path or config.db_path
        self._init_db()

    def _run_or_return(self, coro):
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        return coro

    def _get_conn(self):
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(db_dir, exist_ok=True)
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        db_dir = os.path.dirname(os.path.abspath(self.db_path))
        os.makedirs(db_dir, exist_ok=True)
        with self._get_conn() as conn:
            cursor = conn.cursor()
            cursor.execute("""CREATE TABLE IF NOT EXISTS ucer (
                command_id TEXT PRIMARY KEY, timestamp TEXT, intent TEXT, ucer_json TEXT, 
                state_hash TEXT, status TEXT, canonical_hash TEXT, control_signature TEXT, 
                execution_signature TEXT, execution_pub_key TEXT)""")
            cursor.execute(
                """CREATE TABLE IF NOT EXISTS kv_store (key TEXT PRIMARY KEY, value TEXT, updated_at TEXT)"""
            )
            conn.commit()

    def save_ucer(self, ucer: UCER):
        async def _save():
            await asyncio.to_thread(self._save_ucer_sync, ucer)

        return self._run_or_return(_save())

    def _save_ucer_sync(self, ucer: UCER):
        with self._get_conn() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO ucer (
                command_id, timestamp, intent, ucer_json, state_hash, status, 
                canonical_hash, control_signature, execution_signature, execution_pub_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ucer.command_id,
                    ucer.timestamp.isoformat(),
                    ucer.intent,
                    ucer.model_dump_json(),
                    ucer.state_hash,
                    ucer.status,
                    ucer.canonical_hash,
                    ucer.control_signature,
                    ucer.execution_signature,
                    ucer.execution_pub_key,
                ),
            )

    def get_ucer(self, command_id: str) -> UCER | None:
        async def _get():
            return await asyncio.to_thread(self._get_ucer_sync, command_id)

        return self._run_or_return(_get())

    def _get_ucer_sync(self, command_id: str) -> UCER | None:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT ucer_json FROM ucer WHERE command_id = ?", (command_id,)
            ).fetchone()
            return UCER.model_validate_json(row["ucer_json"]) if row else None

    def list_ucers(self, limit: int = 50) -> list[UCER]:
        def _list():
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT ucer_json FROM ucer ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
                return [UCER.model_validate_json(row["ucer_json"]) for row in rows]

        return self._run_or_return(asyncio.to_thread(_list))

    def set_kv(self, key: str, value: Any):
        def _set():
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO kv_store (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value), datetime.now().isoformat()),
                )

        return self._run_or_return(asyncio.to_thread(_set))

    def get_kv(self, key: str) -> Any | None:
        def _get():
            with self._get_conn() as conn:
                row = conn.execute("SELECT value FROM kv_store WHERE key = ?", (key,)).fetchone()
                return json.loads(row["value"]) if row else None

        return self._run_or_return(asyncio.to_thread(_get))


class NATSDatabase(DatabaseBase):
    """
    Distributed NATS JetStream KV storage.
    Provides strongly consistent, replicated state across the cluster.
    """

    def __init__(self, nats_url: str | None = None):
        self.nats_url = nats_url or config.nats_url
        self.nc = None
        self.js = None
        self.kv_ucer = None
        self.kv_store = None

    async def connect(self):
        if self.nc:
            return
        import nats

        self.nc = await nats.connect(self.nats_url)
        self.js = self.nc.jetstream()
        # Initialize KV stores (bucket name cannot contain underscores in some NATS versions, using alphanumeric)
        self.kv_ucer = await self.js.create_key_value(bucket="UCSERSTATE")
        self.kv_store = await self.js.create_key_value(bucket="UCSERKV")
        logger.info("Connected to NATS KV Store")

    async def close(self):
        if self.nc:
            await self.nc.close()

    async def save_ucer(self, ucer: UCER):
        await self.connect()
        assert self.kv_ucer is not None
        # NATS KV uses dot-separated keys, e.g., ucer.<command_id>
        key = f"ucer.{ucer.command_id}"
        payload = ucer.model_dump_json().encode("utf-8")
        await self.kv_ucer.put(key, payload)

    async def get_ucer(self, command_id: str) -> UCER | None:
        await self.connect()
        assert self.kv_ucer is not None
        try:
            entry = await self.kv_ucer.get(f"ucer.{command_id}")
            return UCER.model_validate_json(entry.value.decode("utf-8"))
        except Exception:
            # KeyNotFoundError or other Jetstream error
            return None

    async def list_ucers(self, limit: int = 50) -> list[UCER]:
        await self.connect()
        assert self.kv_ucer is not None
        try:
            keys = await self.kv_ucer.keys()
            # Fetch latest limit (naive implementation for scaffolding, proper implementation uses watchers)
            # Keys might not be ordered temporally in KV, but we decode and sort
            entries = []
            for key in keys:
                if key.startswith("ucer."):
                    entry = await self.kv_ucer.get(key)
                    entries.append(UCER.model_validate_json(entry.value.decode("utf-8")))

            entries.sort(key=lambda x: x.timestamp, reverse=True)
            return entries[:limit]
        except Exception as e:
            logger.warning(f"Failed to list UCERs from KV: {e}")
            return []

    async def set_kv(self, key: str, value: Any):
        await self.connect()
        assert self.kv_store is not None
        await self.kv_store.put(key, json.dumps(value).encode("utf-8"))

    async def get_kv(self, key: str) -> Any | None:
        await self.connect()
        assert self.kv_store is not None
        try:
            entry = await self.kv_store.get(key)
            return json.loads(entry.value.decode("utf-8"))
        except Exception:
            return None


# For compatibility and migration, provide a factory function or default instance
# In a real environment, this would switch based on config.nats_url presence or a specific flag
Database = SQLiteDatabase
