# -*- coding: utf-8 -*-
"""iCloud HME alias lease pool.

Architecture (P0 + P1 + P2):
- Local inventory is the hot path source of truth for same-machine workers.
- Apple HME note tags remain the cross-device source of truth.
- Registration workers only acquire/commit/release leases; they never list on the hot path.
- Full Apple list is single-flight and only used for sync/warmup/replenish.
- P1: async mark queue + background low-watermark replenisher.
- P2: SQLite inventory (WAL) + operational metrics; JSON auto-migrated.
"""
from __future__ import annotations

import json
import queue
import random
import sqlite3
from contextlib import contextmanager
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from services.register import icloud_hme as hme
from services.register import icloud_note_tags as note_tags

LogFn = Optional[Callable[[str], None]]

STATE_FREE = "free"
STATE_LEASED = "leased"
STATE_REGISTERED = "registered"

DEFAULT_INVENTORY_FILE = "icloud_alias_inventory.db"
DEFAULT_PLATFORM = "chatgpt"
DEFAULT_LEASE_TTL_SEC = 15 * 60
DEFAULT_SYNC_INTERVAL_SEC = 5 * 60
DEFAULT_LOW_WATERMARK = 5
DEFAULT_HIGH_WATERMARK = 20
DEFAULT_REPLENISH_INTERVAL_SEC = 30
DEFAULT_CREATE_PER_CYCLE = 3
DEFAULT_FAIL_COOLDOWN_SEC = 30 * 60
DEFAULT_FAIL_COOLDOWN_MAX_SEC = 24 * 60 * 60
DEFAULT_FAIL_COOLDOWN_THRESHOLD = 3
INVENTORY_VERSION = 1
METRIC_KEYS = (
    "acquire_total",
    "acquire_inventory_hit",
    "acquire_sync_hit",
    "acquire_created",
    "sync_total",
    "sync_fail",
    "sync_duration_ms_total",
    "mark_total",
    "mark_success",
    "mark_fail",
    "create_total",
    "create_fail",
    "release_recycle",
    "release_quarantine",
    "commit_total",
)


def _project_root() -> str:
    try:
        from services.config import DATA_DIR
        return str(DATA_DIR)
    except Exception:
        # services/register/icloud_pool.py -> repo root/data fallback via parents[2]
        return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")


def _resolve_path(path: str = "") -> str:
    raw = (path or DEFAULT_INVENTORY_FILE).strip() or DEFAULT_INVENTORY_FILE
    if os.path.isabs(raw):
        return raw
    return os.path.join(_project_root(), raw)


def _norm_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _now() -> float:
    return time.time()


def _new_lease_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Lease:
    lease_id: str
    email: str
    anonymous_id: str
    platform: str
    source: str
    mark_pending: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Lease":
        return cls(
            lease_id=str(data.get("lease_id") or ""),
            email=_norm_email(data.get("email")),
            anonymous_id=str(data.get("anonymous_id") or ""),
            platform=str(data.get("platform") or DEFAULT_PLATFORM),
            source=str(data.get("source") or "inventory"),
            mark_pending=bool(data.get("mark_pending")),
        )


@dataclass
class AliasRecord:
    email: str
    anonymous_id: str = ""
    label: str = ""
    hme_from_key: str = ""
    note_tags: List[str] = field(default_factory=list)
    state: str = STATE_FREE
    lease_id: str = ""
    lease_owner: str = ""
    lease_expires_at: float = 0.0
    last_seen_at: float = 0.0
    last_marked_at: float = 0.0
    mark_pending: bool = False
    mark_attempts: int = 0
    mark_next_retry_at: float = 0.0
    cooldown_until: float = 0.0
    fail_count: int = 0
    last_fail_reason: str = ""
    is_active: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "anonymous_id": self.anonymous_id,
            "label": self.label,
            "hme_from_key": self.hme_from_key,
            "note_tags": list(self.note_tags),
            "state": self.state,
            "lease_id": self.lease_id,
            "lease_owner": self.lease_owner,
            "lease_expires_at": float(self.lease_expires_at or 0),
            "last_seen_at": float(self.last_seen_at or 0),
            "last_marked_at": float(self.last_marked_at or 0),
            "mark_pending": bool(self.mark_pending),
            "mark_attempts": int(self.mark_attempts or 0),
            "mark_next_retry_at": float(self.mark_next_retry_at or 0),
            "cooldown_until": float(self.cooldown_until or 0),
            "fail_count": int(self.fail_count or 0),
            "last_fail_reason": str(self.last_fail_reason or ""),
            "is_active": bool(self.is_active),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AliasRecord":
        tags = data.get("note_tags") or []
        if isinstance(tags, str):
            tags = note_tags.parse_note_tags(tags)
        elif isinstance(tags, list):
            tags = note_tags.parse_note_tags(",".join(str(x) for x in tags))
        else:
            tags = []
        return cls(
            email=_norm_email(data.get("email")),
            anonymous_id=str(data.get("anonymous_id") or "").strip(),
            label=str(data.get("label") or "").strip(),
            hme_from_key=str(data.get("hme_from_key") or "").strip().lower(),
            note_tags=list(tags),
            state=str(data.get("state") or STATE_FREE),
            lease_id=str(data.get("lease_id") or ""),
            lease_owner=str(data.get("lease_owner") or ""),
            lease_expires_at=float(data.get("lease_expires_at") or 0),
            last_seen_at=float(data.get("last_seen_at") or 0),
            last_marked_at=float(data.get("last_marked_at") or 0),
            mark_pending=bool(data.get("mark_pending")),
            mark_attempts=int(data.get("mark_attempts") or 0),
            mark_next_retry_at=float(data.get("mark_next_retry_at") or 0),
            cooldown_until=float(data.get("cooldown_until") or 0),
            fail_count=int(data.get("fail_count") or 0),
            last_fail_reason=str(data.get("last_fail_reason") or ""),
            is_active=bool(data.get("is_active", True)),
        )


class _FileLock:
    """Best-effort exclusive lock for multi-worker same machine."""

    def __init__(self, path: str, timeout: float = 30.0, poll: float = 0.05):
        self.path = path
        self.timeout = max(float(timeout), 0.5)
        self.poll = max(float(poll), 0.01)
        self._fd: Optional[int] = None

    def __enter__(self) -> "_FileLock":
        deadline = _now() + self.timeout
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        while True:
            try:
                self._fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                os.write(self._fd, str(os.getpid()).encode("ascii", errors="ignore"))
                return self
            except FileExistsError:
                if _now() >= deadline:
                    try:
                        age = _now() - os.path.getmtime(self.path)
                        if age > self.timeout * 2:
                            os.remove(self.path)
                            continue
                    except Exception:
                        pass
                    raise TimeoutError(f"inventory lock timeout: {self.path}")
                time.sleep(self.poll)

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            if self._fd is not None:
                os.close(self._fd)
        finally:
            self._fd = None
            try:
                os.remove(self.path)
            except Exception:
                pass


class _SingleFlight:
    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._event: Optional[threading.Event] = None
        self._result: Any = None
        self._error: Optional[BaseException] = None

    def do(self, fn: Callable[[], Any]) -> Any:
        leader = False
        with self._mu:
            if self._event is None:
                self._event = threading.Event()
                self._result = None
                self._error = None
                leader = True
                event = self._event
            else:
                event = self._event
        if not leader:
            event.wait(timeout=180)
            if self._error is not None:
                raise self._error
            return self._result
        try:
            self._result = fn()
            return self._result
        except BaseException as exc:  # noqa: BLE001
            self._error = exc
            raise
        finally:
            with self._mu:
                event.set()
                self._event = None


class AliasLeaseService:
    """Local inventory + lease state machine for iCloud HME aliases."""

    def __init__(
        self,
        *,
        cookies_raw: str,
        inventory_path: str = "",
        platform: str = DEFAULT_PLATFORM,
        label: str = "chatgpt",
        lease_ttl_sec: float = DEFAULT_LEASE_TTL_SEC,
        sync_interval_sec: float = DEFAULT_SYNC_INTERVAL_SEC,
        reuse_aliases: bool = True,
        create_when_exhausted: bool = True,
        cloud_mark: bool = True,
        coordination_mode: str = "local_fast",
        async_mark: bool = True,
        background_replenish: bool = True,
        low_watermark: int = DEFAULT_LOW_WATERMARK,
        high_watermark: int = DEFAULT_HIGH_WATERMARK,
        replenish_interval_sec: float = DEFAULT_REPLENISH_INTERVAL_SEC,
        create_per_cycle: int = DEFAULT_CREATE_PER_CYCLE,
        fail_cooldown_sec: float = DEFAULT_FAIL_COOLDOWN_SEC,
        fail_cooldown_max_sec: float = DEFAULT_FAIL_COOLDOWN_MAX_SEC,
        fail_cooldown_threshold: int = DEFAULT_FAIL_COOLDOWN_THRESHOLD,
        timeout: float = 25.0,
        auto_start_background: bool = True,
    ) -> None:
        self.cookies_raw = str(cookies_raw or "").strip()
        if not self.cookies_raw:
            raise ValueError("未配置 icloud_cookies")
        self.inventory_path = _resolve_path(inventory_path)
        self.lock_path = self.inventory_path + ".lock"
        self.platform = (str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM)
        self.label = str(label or self.platform or "chatgpt").strip() or "chatgpt"
        self.lease_ttl_sec = max(float(lease_ttl_sec or DEFAULT_LEASE_TTL_SEC), 60.0)
        self.sync_interval_sec = max(float(sync_interval_sec or DEFAULT_SYNC_INTERVAL_SEC), 30.0)
        self.reuse_aliases = bool(reuse_aliases)
        self.create_when_exhausted = bool(create_when_exhausted)
        self.cloud_mark = bool(cloud_mark)
        mode = str(coordination_mode or "local_fast").strip().lower()
        self.coordination_mode = mode if mode in ("local_fast", "cloud_strict") else "local_fast"
        self.async_mark = bool(async_mark) and self.coordination_mode == "local_fast"
        self.background_replenish = bool(background_replenish)
        self.low_watermark = max(int(low_watermark or 0), 0)
        self.high_watermark = max(int(high_watermark or 0), self.low_watermark)
        self.replenish_interval_sec = max(float(replenish_interval_sec or DEFAULT_REPLENISH_INTERVAL_SEC), 5.0)
        self.create_per_cycle = max(int(create_per_cycle or 1), 1)
        self.fail_cooldown_sec = max(float(fail_cooldown_sec or DEFAULT_FAIL_COOLDOWN_SEC), 1.0)
        self.fail_cooldown_max_sec = max(
            float(fail_cooldown_max_sec or DEFAULT_FAIL_COOLDOWN_MAX_SEC),
            self.fail_cooldown_sec,
        )
        self.fail_cooldown_threshold = max(int(fail_cooldown_threshold or DEFAULT_FAIL_COOLDOWN_THRESHOLD), 1)
        self.timeout = float(timeout or 25.0)
        self._sync_flight = _SingleFlight()
        self._mark_q: "queue.Queue[str]" = queue.Queue()
        self._bg_stop = threading.Event()
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_log: LogFn = None
        self._bg_mu = threading.Lock()
        self._last_replenish_at = 0.0
        if auto_start_background and (self.async_mark or self.background_replenish):
            self.start_background()

    def _empty_inventory(self) -> Dict[str, Any]:
        return {
            "version": INVENTORY_VERSION,
            "platform": self.platform,
            "last_full_sync_at": 0.0,
            "aliases": {},
            "metrics": {k: 0.0 for k in METRIC_KEYS},
        }

    def _db_path(self) -> str:
        path = self.inventory_path
        if path.lower().endswith(".json"):
            return path[:-5] + ".db"
        if path.lower().endswith(".db"):
            return path
        return path + ".db"

    def _json_legacy_path(self) -> str:
        path = self.inventory_path
        if path.lower().endswith(".json"):
            return path
        if path.lower().endswith(".db"):
            return path[:-3] + ".json"
        return path + ".json"

    def _connect(self) -> sqlite3.Connection:
        db_path = self._db_path()
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=60.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA temp_store=MEMORY")
        self._ensure_schema(conn)
        self._maybe_migrate_json(conn)
        return conn

    def _ensure_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS aliases (
                email TEXT PRIMARY KEY,
                anonymous_id TEXT NOT NULL DEFAULT '',
                label TEXT NOT NULL DEFAULT '',
                hme_from_key TEXT NOT NULL DEFAULT '',
                note_tags TEXT NOT NULL DEFAULT '',
                state TEXT NOT NULL DEFAULT 'free',
                lease_id TEXT NOT NULL DEFAULT '',
                lease_owner TEXT NOT NULL DEFAULT '',
                lease_expires_at REAL NOT NULL DEFAULT 0,
                last_seen_at REAL NOT NULL DEFAULT 0,
                last_marked_at REAL NOT NULL DEFAULT 0,
                mark_pending INTEGER NOT NULL DEFAULT 0,
                mark_attempts INTEGER NOT NULL DEFAULT 0,
                mark_next_retry_at REAL NOT NULL DEFAULT 0,
                cooldown_until REAL NOT NULL DEFAULT 0,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_fail_reason TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS metrics (
                key TEXT PRIMARY KEY,
                value REAL NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_aliases_state_active
                ON aliases(state, is_active);
            """
        )
        # migrate older DBs
        cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(aliases)").fetchall()}
        alter_map = {
            "label": "TEXT NOT NULL DEFAULT ''",
            "hme_from_key": "TEXT NOT NULL DEFAULT ''",
            "mark_attempts": "INTEGER NOT NULL DEFAULT 0",
            "mark_next_retry_at": "REAL NOT NULL DEFAULT 0",
            "cooldown_until": "REAL NOT NULL DEFAULT 0",
            "fail_count": "INTEGER NOT NULL DEFAULT 0",
            "last_fail_reason": "TEXT NOT NULL DEFAULT ''",
        }
        for col, decl in alter_map.items():
            if col not in cols:
                conn.execute(f"ALTER TABLE aliases ADD COLUMN {col} {decl}")

        for key in METRIC_KEYS:
            conn.execute(
                "INSERT OR IGNORE INTO metrics(key, value) VALUES (?, 0)",
                (key,),
            )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('version', ?)",
            (str(INVENTORY_VERSION),),
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('platform', ?)",
            (self.platform,),
        )
        conn.execute(
            "INSERT OR IGNORE INTO meta(key, value) VALUES ('last_full_sync_at', '0')",
        )

    def _maybe_migrate_json(self, conn: sqlite3.Connection) -> None:
        row = conn.execute("SELECT COUNT(*) AS c FROM aliases").fetchone()
        if row and int(row["c"] or 0) > 0:
            return
        legacy = self._json_legacy_path()
        # also try original inventory_path if json
        candidates = []
        for p in (legacy, self.inventory_path):
            if p and p not in candidates:
                candidates.append(p)
        for path in candidates:
            if not path or not os.path.isfile(path) or not path.lower().endswith(".json"):
                continue
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            aliases = data.get("aliases") or {}
            if not isinstance(aliases, dict) or not aliases:
                # maybe empty but still migrate meta
                pass
            conn.execute("BEGIN IMMEDIATE")
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_full_sync_at', ?)",
                    (str(float(data.get("last_full_sync_at") or 0)),),
                )
                conn.execute(
                    "INSERT OR REPLACE INTO meta(key, value) VALUES ('platform', ?)",
                    (str(data.get("platform") or self.platform),),
                )
                for key, value in aliases.items():
                    if not isinstance(value, dict):
                        continue
                    rec = AliasRecord.from_dict(value)
                    email = rec.email or _norm_email(key)
                    if not email:
                        continue
                    rec.email = email
                    self._upsert_alias_conn(conn, rec)
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
            break

    def _upsert_alias_conn(self, conn: sqlite3.Connection, rec: "AliasRecord") -> None:
        conn.execute(
            """
            INSERT INTO aliases(
                email, anonymous_id, label, hme_from_key, note_tags, state, lease_id, lease_owner,
                lease_expires_at, last_seen_at, last_marked_at, mark_pending,
                mark_attempts, mark_next_retry_at, cooldown_until, fail_count, last_fail_reason, is_active
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                anonymous_id=excluded.anonymous_id,
                label=excluded.label,
                hme_from_key=excluded.hme_from_key,
                note_tags=excluded.note_tags,
                state=excluded.state,
                lease_id=excluded.lease_id,
                lease_owner=excluded.lease_owner,
                lease_expires_at=excluded.lease_expires_at,
                last_seen_at=excluded.last_seen_at,
                last_marked_at=excluded.last_marked_at,
                mark_pending=excluded.mark_pending,
                mark_attempts=excluded.mark_attempts,
                mark_next_retry_at=excluded.mark_next_retry_at,
                cooldown_until=excluded.cooldown_until,
                fail_count=excluded.fail_count,
                last_fail_reason=excluded.last_fail_reason,
                is_active=excluded.is_active
            """,
            (
                rec.email,
                rec.anonymous_id or "",
                rec.label or "",
                rec.hme_from_key or "",
                ",".join(rec.note_tags or []),
                rec.state or STATE_FREE,
                rec.lease_id or "",
                rec.lease_owner or "",
                float(rec.lease_expires_at or 0),
                float(rec.last_seen_at or 0),
                float(rec.last_marked_at or 0),
                1 if rec.mark_pending else 0,
                int(rec.mark_attempts or 0),
                float(rec.mark_next_retry_at or 0),
                float(rec.cooldown_until or 0),
                int(rec.fail_count or 0),
                str(rec.last_fail_reason or "")[:200],
                1 if rec.is_active else 0,
            ),
        )


    def _load_metrics_conn(self, conn: sqlite3.Connection) -> Dict[str, float]:
        out = {k: 0.0 for k in METRIC_KEYS}
        for row in conn.execute("SELECT key, value FROM metrics"):
            key = str(row["key"] or "")
            if key in out:
                out[key] = float(row["value"] or 0)
        return out

    def _save_metrics_conn(self, conn: sqlite3.Connection, metrics: Dict[str, float]) -> None:
        for key in METRIC_KEYS:
            conn.execute(
                "INSERT INTO metrics(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, float(metrics.get(key, 0) or 0)),
            )

    def _load_unlocked(self, conn: Optional[sqlite3.Connection] = None) -> Dict[str, Any]:
        owns = conn is None
        if owns:
            conn = self._connect()
        try:
            data = self._empty_inventory()
            for row in conn.execute("SELECT key, value FROM meta"):
                key = str(row["key"] or "")
                val = str(row["value"] or "")
                if key == "last_full_sync_at":
                    try:
                        data["last_full_sync_at"] = float(val)
                    except Exception:
                        data["last_full_sync_at"] = 0.0
                elif key == "platform" and val:
                    data["platform"] = val
                elif key == "version":
                    try:
                        data["version"] = int(val)
                    except Exception:
                        data["version"] = INVENTORY_VERSION
            aliases: Dict[str, Any] = {}
            for row in conn.execute("SELECT * FROM aliases"):
                keys = set(row.keys())
                rec = AliasRecord(
                    email=_norm_email(row["email"]),
                    anonymous_id=str(row["anonymous_id"] or ""),
                    label=str(row["label"] or "") if "label" in keys else "",
                    hme_from_key=str(row["hme_from_key"] or "").strip().lower() if "hme_from_key" in keys else "",
                    note_tags=note_tags.parse_note_tags(str(row["note_tags"] or "")),
                    state=str(row["state"] or STATE_FREE),
                    lease_id=str(row["lease_id"] or ""),
                    lease_owner=str(row["lease_owner"] or ""),
                    lease_expires_at=float(row["lease_expires_at"] or 0),
                    last_seen_at=float(row["last_seen_at"] or 0),
                    last_marked_at=float(row["last_marked_at"] or 0),
                    mark_pending=bool(int(row["mark_pending"] or 0)),
                    mark_attempts=int(row["mark_attempts"] or 0) if "mark_attempts" in keys else 0,
                    mark_next_retry_at=float(row["mark_next_retry_at"] or 0) if "mark_next_retry_at" in keys else 0.0,
                    cooldown_until=float(row["cooldown_until"] or 0) if "cooldown_until" in keys else 0.0,
                    fail_count=int(row["fail_count"] or 0) if "fail_count" in keys else 0,
                    last_fail_reason=str(row["last_fail_reason"] or "") if "last_fail_reason" in keys else "",
                    is_active=bool(int(row["is_active"] or 0)),
                )
                if rec.email:
                    aliases[rec.email] = rec.to_dict()
            data["aliases"] = aliases
            data["metrics"] = self._load_metrics_conn(conn)
            return data
        finally:
            if owns:
                conn.close()

    def _save_unlocked(self, data: Dict[str, Any], conn: Optional[sqlite3.Connection] = None) -> None:
        owns = conn is None
        if owns:
            conn = self._connect()
            conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('version', ?)",
                (str(INVENTORY_VERSION),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('platform', ?)",
                (str(data.get("platform") or self.platform),),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES ('last_full_sync_at', ?)",
                (str(float(data.get("last_full_sync_at") or 0)),),
            )
            records = self._records(data)
            # replace all aliases for simplicity and consistency with previous JSON rewrite semantics
            conn.execute("DELETE FROM aliases")
            for rec in records.values():
                self._upsert_alias_conn(conn, rec)
            metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
            merged = {k: float(metrics.get(k, 0) or 0) for k in METRIC_KEYS}
            self._save_metrics_conn(conn, merged)
            if owns:
                conn.execute("COMMIT")
        except Exception:
            if owns:
                conn.execute("ROLLBACK")
            raise
        finally:
            if owns:
                conn.close()

    @contextmanager
    def _tx(self):
        """Exclusive inventory transaction (SQLite BEGIN IMMEDIATE)."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    def _metric_add(self, data: Dict[str, Any], key: str, delta: float = 1.0) -> None:
        metrics = data.setdefault("metrics", {k: 0.0 for k in METRIC_KEYS})
        if not isinstance(metrics, dict):
            metrics = {k: 0.0 for k in METRIC_KEYS}
            data["metrics"] = metrics
        metrics[key] = float(metrics.get(key, 0) or 0) + float(delta)

    def _records(self, data: Dict[str, Any]) -> Dict[str, AliasRecord]:
        out: Dict[str, AliasRecord] = {}
        raw_aliases = data.get("aliases") or {}
        if not isinstance(raw_aliases, dict):
            return out
        for key, value in raw_aliases.items():
            if not isinstance(value, dict):
                continue
            rec = AliasRecord.from_dict(value)
            email = rec.email or _norm_email(key)
            if not email:
                continue
            rec.email = email
            out[email] = rec
        return out

    def _dump_records(self, data: Dict[str, Any], records: Dict[str, AliasRecord]) -> None:
        data["aliases"] = {email: rec.to_dict() for email, rec in sorted(records.items())}

    def _expire_leases(self, records: Dict[str, AliasRecord], now: Optional[float] = None) -> int:
        ts = float(now or _now())
        n = 0
        for rec in records.values():
            if rec.state != STATE_LEASED:
                continue
            exp = float(rec.lease_expires_at or 0)
            if exp and exp <= ts:
                # optimistic local tags (mark_pending) should not permanently burn an alias
                if rec.last_marked_at or (self.platform in rec.note_tags and not rec.mark_pending):
                    rec.state = STATE_REGISTERED
                else:
                    rec.note_tags = [tag for tag in rec.note_tags if tag != self.platform]
                    rec.state = STATE_FREE
                    # abandoned/expired lease: cool down so same bad alias is not immediately re-picked
                    self._apply_fail_cooldown(rec, reason="lease_expired")
                rec.lease_id = ""
                rec.lease_owner = ""
                rec.lease_expires_at = 0.0
                rec.mark_pending = False
                n += 1
        return n

    def _counts(self, records: Dict[str, AliasRecord]) -> Dict[str, int]:
        free = leased = registered = inactive = cooling = 0
        now = _now()
        for rec in records.values():
            if not rec.is_active:
                inactive += 1
                continue
            if rec.state == STATE_FREE:
                if float(rec.cooldown_until or 0) > now:
                    cooling += 1
                else:
                    free += 1
            elif rec.state == STATE_LEASED:
                leased += 1
            elif rec.state == STATE_REGISTERED:
                registered += 1
        return {
            "total": len(records),
            "free": free,
            "cooling": cooling,
            "leased": leased,
            "registered": registered,
            "inactive": inactive,
        }

    def _apply_fail_cooldown(
        self,
        rec: "AliasRecord",
        *,
        cooldown_sec: Optional[float] = None,
        reason: str = "",
    ) -> float:
        """Count a failure; only enter cooldown after threshold failures.

        Returns applied cooldown delay seconds (0 if still under threshold).
        """
        rec.fail_count = int(rec.fail_count or 0) + 1
        rec.last_fail_reason = str(reason or "")[:200]
        threshold = max(int(self.fail_cooldown_threshold or DEFAULT_FAIL_COOLDOWN_THRESHOLD), 1)
        if int(rec.fail_count) < threshold:
            # keep alias immediately re-pickable until threshold is reached
            rec.cooldown_until = 0.0
            return 0.0
        base = float(self.fail_cooldown_sec if cooldown_sec is None else cooldown_sec)
        base = max(base, 1.0)
        # first cooldown at threshold uses base; then exponential
        level = max(int(rec.fail_count) - threshold + 1, 1)
        delay = min(float(self.fail_cooldown_max_sec), base * (2 ** (level - 1)))
        rec.cooldown_until = _now() + delay
        return float(delay)


    def _pick_free(self, records: Dict[str, AliasRecord]) -> Optional[AliasRecord]:
        now = _now()
        candidates = []
        for rec in records.values():
            if not rec.is_active or rec.state != STATE_FREE:
                continue
            if self.platform in rec.note_tags:
                continue
            # skip aliases still in failure cooldown
            if float(rec.cooldown_until or 0) > now:
                continue
            candidates.append(rec)
        if not candidates:
            return None
        # prefer fewer failures; randomize within the same fail_count bucket
        min_fails = min(int(r.fail_count or 0) for r in candidates)
        bucket = [r for r in candidates if int(r.fail_count or 0) == min_fails]
        return random.choice(bucket)


    def _lease_record(
        self,
        rec: AliasRecord,
        *,
        owner: str,
        source: str,
        mark_pending: bool,
    ) -> Lease:
        lease_id = _new_lease_id()
        rec.state = STATE_LEASED
        rec.lease_id = lease_id
        rec.lease_owner = str(owner or "")
        rec.lease_expires_at = _now() + self.lease_ttl_sec
        rec.mark_pending = bool(mark_pending)
        if mark_pending and self.platform not in rec.note_tags:
            rec.note_tags = note_tags.parse_note_tags(
                note_tags.note_add_platform(",".join(rec.note_tags), self.platform)
            )
        return Lease(
            lease_id=lease_id,
            email=rec.email,
            anonymous_id=rec.anonymous_id or rec.email,
            platform=self.platform,
            source=source,
            mark_pending=bool(mark_pending),
        )

    def _lookup_remote_label(self, anonymous_id: str) -> str:
        """Fetch current Apple HME label so we can preserve it on note-only updates."""
        anon = str(anonymous_id or "").strip()
        if not anon:
            return ""
        cookies = hme.parse_icloud_account_cookies(self.cookies_raw)
        client = hme.ICloudHideMyEmailClient(cookies, timeout=self.timeout)
        try:
            for item in client.list_aliases():
                if str(getattr(item, "anonymous_id", "") or "").strip() == anon:
                    return str(getattr(item, "label", "") or "").strip()
        finally:
            client.close()
        return ""

    def _cloud_mark(self, rec: AliasRecord, log_callback: LogFn = None) -> None:
        """Write platform tag into HME note only. Never invent/overwrite label with grok."""
        if not self.cloud_mark:
            return
        anon = str(rec.anonymous_id or "").strip()
        if not anon:
            raise RuntimeError(f"missing anonymous_id for {rec.email}")
        new_note = note_tags.format_note_tags(rec.note_tags or [self.platform])
        if self.platform not in note_tags.parse_note_tags(new_note):
            new_note = note_tags.note_add_platform(new_note, self.platform)

        # Preserve existing label only. Never invent/overwrite with "grok".
        label = str(rec.label or "").strip()
        cookies = hme.parse_icloud_account_cookies(self.cookies_raw)
        client = hme.ICloudHideMyEmailClient(cookies, timeout=self.timeout)
        try:
            try:
                if label:
                    client.update_metadata(anon, label=label, note=new_note)
                else:
                    # note-only first; fetch label only if Apple rejects missing label
                    client.update_metadata(anon, note=new_note)
            except Exception as exc:
                msg = str(exc).lower()
                if "invalid label" in msg and not label:
                    label = self._lookup_remote_label(anon)
                    if not label:
                        raise
                    rec.label = label
                    client.update_metadata(anon, label=label, note=new_note)
                else:
                    raise
        finally:
            client.close()
        rec.note_tags = note_tags.parse_note_tags(new_note)
        rec.last_marked_at = _now()
        rec.mark_pending = False
        rec.mark_attempts = 0
        rec.mark_next_retry_at = 0.0
        if log_callback:
            log_callback(
                f"[*] iCloud note 已标记平台 [{self.platform}]: note={new_note}"
                + (f" (label保持={label})" if label else " (未改label)")
            )

    def _create_remote_alias(
        self,
        log_callback: LogFn = None,
        *,
        mark_platform: bool = True,
    ) -> AliasRecord:
        create_note = (
            note_tags.note_add_platform("", self.platform)
            if self.cloud_mark and mark_platform
            else ""
        )
        cookies = hme.parse_icloud_account_cookies(self.cookies_raw)
        client = hme.ICloudHideMyEmailClient(cookies, timeout=self.timeout)
        try:
            alias = client.create_alias(label=self.label or self.platform, note=create_note)
        finally:
            client.close()
        email = _norm_email(alias.email)
        anon = str(alias.anonymous_id or "").strip()
        if not email or "@" not in email:
            raise RuntimeError("iCloud HME 未返回有效别名邮箱")
        rec = AliasRecord(
            email=email,
            anonymous_id=anon,
            label=str(self.label or self.platform or "chatgpt"),
            note_tags=note_tags.parse_note_tags(create_note),
            state=STATE_FREE,
            last_seen_at=_now(),
            last_marked_at=_now() if self.cloud_mark else 0.0,
            mark_pending=False,
            is_active=True,
        )
        if log_callback:
            log_callback(f"[*] 已新建 iCloud 别名: {email} note={create_note or '-'}")
        return rec

    def create_free_aliases(self, count: int, *, log_callback: LogFn = None) -> Dict[str, Any]:
        """Create aliases for inventory without marking them as already registered."""
        target = max(1, int(count or 1))
        result: Dict[str, Any] = {
            "requested_count": target,
            "created_count": 0,
            "failed_count": 0,
            "emails": [],
            "errors": [],
        }
        for _ in range(target):
            try:
                created = self._create_remote_alias(
                    log_callback=log_callback,
                    mark_platform=False,
                )
                with self._tx() as conn:
                    data = self._load_unlocked(conn)
                    records = self._records(data)
                    created.state = STATE_FREE
                    created.mark_pending = False
                    records[created.email] = created
                    self._dump_records(data, records)
                    self._metric_add(data, "create_total")
                    self._save_unlocked(data, conn)
                result["created_count"] += 1
                result["emails"].append(created.email)
            except Exception as exc:
                result["failed_count"] += 1
                result["errors"].append(str(exc))
                try:
                    with self._tx() as conn:
                        data = self._load_unlocked(conn)
                        self._metric_add(data, "create_fail")
                        self._save_unlocked(data, conn)
                except Exception:
                    pass
                if log_callback:
                    log_callback(f"[!] iCloud 定时创建失败：{exc}")
                break
        return result

    def _sync_from_apple(self, log_callback: LogFn = None) -> Dict[str, int]:
        def _run() -> Dict[str, int]:
            started = _now()
            cookies = hme.parse_icloud_account_cookies(self.cookies_raw)
            client = hme.ICloudHideMyEmailClient(cookies, timeout=self.timeout)
            try:
                remote_list = client.list_aliases()
            finally:
                client.close()

            with self._tx() as conn:
                data = self._load_unlocked(conn)
                records = self._records(data)
                self._expire_leases(records)
                now = _now()
                seen = set()
                for item in remote_list:
                    email = _norm_email(getattr(item, "email", ""))
                    if not email:
                        continue
                    seen.add(email)
                    tags = note_tags.parse_note_tags(getattr(item, "note", "") or "")
                    anon = str(getattr(item, "anonymous_id", "") or "").strip()
                    is_active = bool(getattr(item, "is_active", True))
                    rec = records.get(email) or AliasRecord(email=email)
                    rec.email = email
                    rec.anonymous_id = anon or rec.anonymous_id
                    apple_label = str(getattr(item, "label", "") or "").strip()
                    if apple_label:
                        rec.label = apple_label
                    rec.note_tags = tags
                    rec.is_active = is_active
                    rec.last_seen_at = now
                    remote_registered = self.platform in tags
                    if not is_active:
                        if remote_registered:
                            rec.state = STATE_REGISTERED
                        rec.lease_id = ""
                        rec.lease_owner = ""
                        rec.lease_expires_at = 0.0
                        rec.mark_pending = False
                    elif remote_registered:
                        rec.state = STATE_REGISTERED
                        rec.lease_id = ""
                        rec.lease_owner = ""
                        rec.lease_expires_at = 0.0
                        rec.mark_pending = False
                    else:
                        if rec.state == STATE_LEASED and float(rec.lease_expires_at or 0) > now:
                            pass
                        else:
                            rec.state = STATE_FREE
                            rec.lease_id = ""
                            rec.lease_owner = ""
                            rec.lease_expires_at = 0.0
                            rec.mark_pending = False
                    records[email] = rec

                for email, rec in list(records.items()):
                    if email in seen:
                        continue
                    if rec.state == STATE_FREE:
                        rec.is_active = False

                self._dump_records(data, records)
                data["last_full_sync_at"] = now
                elapsed_ms = max((_now() - started) * 1000.0, 0.0)
                self._metric_add(data, "sync_total")
                self._metric_add(data, "sync_duration_ms_total", elapsed_ms)
                self._save_unlocked(data, conn)
                counts = self._counts(records)
                counts["sync_duration_ms"] = elapsed_ms
            if log_callback:
                log_callback(
                    f"[*] iCloud 库存同步完成: total={counts['total']} free={counts['free']} cooling={counts.get('cooling', 0)} "
                    f"leased={counts['leased']} registered={counts['registered']} "
                    f"({counts.get('sync_duration_ms', 0):.0f}ms)"
                )
            return counts

        try:
            return self._sync_flight.do(_run)
        except Exception:
            try:
                with self._tx() as conn:
                    data = self._load_unlocked(conn)
                    self._metric_add(data, "sync_fail")
                    self._save_unlocked(data, conn)
            except Exception:
                pass
            raise

    def _needs_sync(self, data: Dict[str, Any], records: Dict[str, AliasRecord]) -> bool:
        if not self.reuse_aliases:
            return False
        last = float(data.get("last_full_sync_at") or 0)
        if last <= 0:
            return True
        if (_now() - last) >= self.sync_interval_sec:
            return True
        if self._counts(records)["free"] <= 0:
            return True
        return False

    def sync(self, *, force: bool = False, log_callback: LogFn = None) -> Dict[str, int]:
        if not force:
            with self._tx() as conn:
                data = self._load_unlocked(conn)
                records = self._records(data)
                self._expire_leases(records)
                if not self._needs_sync(data, records):
                    return self._counts(records)
                self._dump_records(data, records)
                self._save_unlocked(data, conn)
        return self._sync_from_apple(log_callback=log_callback)

    def acquire(self, *, owner: str = "", log_callback: LogFn = None) -> Lease:
        owner = str(owner or f"pid:{os.getpid()}")
        lease = self._acquire_from_inventory(owner=owner, source="inventory", log_callback=log_callback)
        if lease is not None:
            return self._after_acquire(lease, log_callback=log_callback)

        if self.reuse_aliases:
            try:
                self._sync_from_apple(log_callback=log_callback)
            except Exception as exc:
                if log_callback:
                    log_callback(f"[!] iCloud 库存同步失败，将尝试新建: {exc}")
            lease = self._acquire_from_inventory(owner=owner, source="sync", log_callback=log_callback)
            if lease is not None:
                return self._after_acquire(lease, log_callback=log_callback)

        if not self.create_when_exhausted:
            raise RuntimeError(
                "iCloud 无可用未注册别名，且未开启自动新建（icloud_create_when_exhausted=false）"
            )
        if log_callback:
            log_callback("[*] iCloud 库存无可用别名，正在新建 Hide My Email...")
        created = self._create_remote_alias(log_callback=log_callback)
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            self._expire_leases(records)
            records[created.email] = created
            lease = self._lease_record(
                created,
                owner=owner,
                source="created",
                mark_pending=False,
            )
            self._dump_records(data, records)
            self._save_unlocked(data, conn)
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            self._metric_add(data, "acquire_total")
            self._metric_add(data, "acquire_created")
            self._metric_add(data, "create_total")
            self._save_unlocked(data, conn)
        if log_callback:
            log_callback(f"[*] 租约领取(created): {lease.email}")
        return lease

    def _acquire_from_inventory(
        self,
        *,
        owner: str,
        source: str,
        log_callback: LogFn = None,
    ) -> Optional[Lease]:
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            self._expire_leases(records)
            rec = self._pick_free(records)
            if rec is None:
                self._dump_records(data, records)
                self._save_unlocked(data, conn)
                return None
            # local_fast: only local lease for concurrency; cloud note is written on commit only.
            # cloud_strict: claim immediately via note to coordinate multi-machine.
            if self.coordination_mode == "cloud_strict":
                mark_pending = bool(self.cloud_mark)
            else:
                mark_pending = False
            lease = self._lease_record(
                rec,
                owner=owner,
                source=source,
                mark_pending=mark_pending,
            )
            self._dump_records(data, records)
            self._save_unlocked(data, conn)
            counts = self._counts(records)
        # metrics persisted by caller transaction already closed; bump in short tx
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            self._metric_add(data, "acquire_total")
            if source == "inventory":
                self._metric_add(data, "acquire_inventory_hit")
            elif source == "sync":
                self._metric_add(data, "acquire_sync_hit")
            self._save_unlocked(data, conn)
        if log_callback:
            log_callback(
                f"[*] iCloud 库存命中: free剩余约{max(counts['free'], 0)} | 领取 {lease.email} ({source})"
            )
        if self.background_replenish and int(counts.get("free") or 0) < self.low_watermark:
            # non-blocking: let background loop refill soon
            self._last_replenish_at = 0.0
            self.start_background(log_callback=log_callback)
        return lease

    def _after_acquire(self, lease: Lease, log_callback: LogFn = None) -> Lease:
        if not lease.mark_pending:
            return lease
        if self.coordination_mode == "cloud_strict":
            with self._tx() as conn:
                data = self._load_unlocked(conn)
                records = self._records(data)
                rec = records.get(lease.email)
                if rec is None:
                    return lease
                try:
                    self._cloud_mark(rec, log_callback=log_callback)
                except Exception as exc:
                    rec.state = STATE_FREE
                    rec.lease_id = ""
                    rec.lease_owner = ""
                    rec.lease_expires_at = 0.0
                    rec.mark_pending = False
                    rec.note_tags = [tag for tag in rec.note_tags if tag != self.platform]
                    self._dump_records(data, records)
                    self._save_unlocked(data, conn)
                    raise RuntimeError(f"cloud_strict 标记 note 失败: {exc}") from exc
                lease.mark_pending = False
                self._dump_records(data, records)
                self._save_unlocked(data, conn)
            return lease
        # local_fast: non-blocking mark via background queue
        if self.async_mark and self.cloud_mark:
            self._enqueue_mark(lease.email)
        return lease

    def commit(
        self,
        *,
        lease_id: str = "",
        email: str = "",
        log_callback: LogFn = None,
    ) -> None:
        email_n = _norm_email(email)
        lease_id = str(lease_id or "").strip()
        need_mark = False
        anon = ""
        tags: List[str] = []
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            rec = None
            if lease_id:
                for item in records.values():
                    if item.lease_id == lease_id:
                        rec = item
                        break
            if rec is None and email_n:
                rec = records.get(email_n)
            if rec is None:
                if email_n:
                    rec = AliasRecord(
                        email=email_n,
                        note_tags=[self.platform],
                        state=STATE_REGISTERED,
                        last_marked_at=_now() if self.cloud_mark else 0.0,
                    )
                    records[email_n] = rec
                else:
                    return
            if self.platform not in rec.note_tags:
                rec.note_tags = note_tags.parse_note_tags(
                    note_tags.note_add_platform(",".join(rec.note_tags), self.platform)
                )
            rec.state = STATE_REGISTERED
            rec.lease_id = ""
            rec.lease_owner = ""
            rec.lease_expires_at = 0.0
            rec.cooldown_until = 0.0
            rec.fail_count = 0
            rec.last_fail_reason = ""
            if rec.last_marked_at and self.platform in rec.note_tags and not rec.mark_pending:
                need_mark = False
            else:
                need_mark = bool(self.cloud_mark)
            rec.mark_pending = bool(need_mark)
            email_n = rec.email
            anon = rec.anonymous_id
            tags = list(rec.note_tags)
            self._metric_add(data, "commit_total")
            self._dump_records(data, records)
            self._save_unlocked(data, conn)

        if not need_mark:
            if log_callback:
                log_callback(f"[*] iCloud 租约已提交(本地): {email_n}")
            return

        if self.async_mark and self.cloud_mark:
            self._enqueue_mark(email_n)
            if log_callback:
                log_callback(f"[*] iCloud note 标记已入队: {email_n}")
            return

        try:
            with self._tx() as conn:
                data = self._load_unlocked(conn)
                records = self._records(data)
                rec = records.get(email_n)
                if rec is None:
                    rec = AliasRecord(email=email_n, anonymous_id=anon, note_tags=tags)
                    records[email_n] = rec
                rec.state = STATE_REGISTERED
                rec.note_tags = tags if tags else [self.platform]
                if not rec.anonymous_id:
                    rec.anonymous_id = anon
                self._cloud_mark(rec, log_callback=log_callback)
                self._dump_records(data, records)
                self._save_unlocked(data, conn)
        except Exception as exc:
            if log_callback:
                log_callback(f"[!] 注册成功后写 iCloud note 失败: {exc}")

    def release(
        self,
        *,
        lease_id: str = "",
        email: str = "",
        recycle: bool = True,
        cooldown: bool = True,
        cooldown_sec: Optional[float] = None,
        reason: str = "",
        log_callback: LogFn = None,
    ) -> None:
        email_n = _norm_email(email)
        lease_id = str(lease_id or "").strip()
        action = ""
        released_email = ""
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            rec = None
            if lease_id:
                for item in records.values():
                    if item.lease_id == lease_id:
                        rec = item
                        break
            if rec is None and email_n:
                rec = records.get(email_n)
            if rec is None:
                return
            # Cloud note is only authoritative after successful mark (last_marked_at).
            already_marked = bool(rec.last_marked_at)
            if recycle and not already_marked:
                rec.note_tags = [tag for tag in rec.note_tags if tag != self.platform]
                rec.state = STATE_FREE
                rec.mark_pending = False
                rec.mark_attempts = 0
                rec.mark_next_retry_at = 0.0
                if cooldown:
                    delay = self._apply_fail_cooldown(
                        rec,
                        cooldown_sec=cooldown_sec,
                        reason=reason,
                    )
                    if delay > 0:
                        action = f"冷却{int(delay)}s(fail#{rec.fail_count}/{self.fail_cooldown_threshold})"
                    else:
                        action = f"回收为free(fail#{rec.fail_count}/{self.fail_cooldown_threshold})"
                else:
                    # clean recycle: clear residual cooldown so alias is immediately usable
                    rec.cooldown_until = 0.0
                    action = "回收为free"
                self._metric_add(data, "release_recycle")
            else:
                if self.platform not in rec.note_tags:
                    rec.note_tags = note_tags.parse_note_tags(
                        note_tags.note_add_platform(",".join(rec.note_tags), self.platform)
                    )
                rec.state = STATE_REGISTERED
                rec.mark_pending = False
                action = "隔离为registered"
                self._metric_add(data, "release_quarantine")
            rec.lease_id = ""
            rec.lease_owner = ""
            rec.lease_expires_at = 0.0
            released_email = rec.email
            self._dump_records(data, records)
            self._save_unlocked(data, conn)
        if log_callback:
            log_callback(f"[*] iCloud 租约释放({action}): {released_email}")


    # ------------------------------------------------------------------ P1 background
    def _enqueue_mark(self, email: str) -> None:
        addr = _norm_email(email)
        if not addr:
            return
        self.start_background()
        self._mark_q.put(addr)

    def start_background(self, log_callback: LogFn = None) -> None:
        with self._bg_mu:
            if log_callback is not None:
                self._bg_log = log_callback
            if self._bg_thread and self._bg_thread.is_alive():
                return
            self._bg_stop.clear()
            self._bg_thread = threading.Thread(
                target=self._background_loop,
                name="icloud-alias-pool-bg",
                daemon=True,
            )
            self._bg_thread.start()

    def stop_background(self, *, flush_marks: bool = False, timeout: float = 5.0) -> None:
        if flush_marks:
            self.flush_marks(timeout=timeout)
        self._bg_stop.set()
        # wake queue waiter
        try:
            self._mark_q.put_nowait("")
        except Exception:
            pass
        th = self._bg_thread
        if th and th.is_alive():
            th.join(timeout=max(float(timeout), 0.1))

    def flush_marks(self, timeout: float = 10.0) -> int:
        """Process pending mark jobs synchronously. Returns processed count."""
        deadline = _now() + max(float(timeout), 0.1)
        processed = 0
        # drain queue first
        while _now() < deadline:
            try:
                email = self._mark_q.get_nowait()
            except queue.Empty:
                break
            if not email:
                continue
            if self._process_mark_email(email, log_callback=self._bg_log):
                processed += 1
        # then scan inventory for leftovers
        while _now() < deadline:
            email = self._next_mark_pending_email()
            if not email:
                break
            if self._process_mark_email(email, log_callback=self._bg_log):
                processed += 1
            else:
                break
        return processed

    def _next_mark_pending_email(self) -> str:
        now = _now()
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            for email, rec in sorted(records.items()):
                if not rec.mark_pending or not rec.anonymous_id:
                    continue
                if float(rec.mark_next_retry_at or 0) > now:
                    continue
                return email
        return ""

    def _process_mark_email(self, email: str, log_callback: LogFn = None) -> bool:
        addr = _norm_email(email)
        if not addr or not self.cloud_mark:
            return False
        try:
            with self._tx() as conn:
                data = self._load_unlocked(conn)
                records = self._records(data)
                rec = records.get(addr)
                if rec is None:
                    return False
                if not rec.mark_pending and rec.last_marked_at and self.platform in rec.note_tags:
                    return False
                if float(rec.mark_next_retry_at or 0) > _now():
                    return False
                if self.platform not in rec.note_tags:
                    rec.note_tags = note_tags.parse_note_tags(
                        note_tags.note_add_platform(",".join(rec.note_tags), self.platform)
                    )
                self._cloud_mark(rec, log_callback=log_callback)
                self._metric_add(data, "mark_total")
                self._metric_add(data, "mark_success")
                self._dump_records(data, records)
                self._save_unlocked(data, conn)
            return True
        except Exception as exc:
            try:
                with self._tx() as conn:
                    data = self._load_unlocked(conn)
                    records = self._records(data)
                    rec = records.get(addr)
                    self._metric_add(data, "mark_total")
                    self._metric_add(data, "mark_fail")
                    if rec is not None:
                        rec.mark_attempts = int(rec.mark_attempts or 0) + 1
                        # exponential backoff: 10s, 20s, 40s... cap 5min
                        delay = min(300.0, 10.0 * (2 ** max(rec.mark_attempts - 1, 0)))
                        rec.mark_next_retry_at = _now() + delay
                        # give up after several permanent-looking failures
                        msg = str(exc).lower()
                        permanent = ("invalid label" in msg) or ("unauthorized" in msg) or ("auth" in msg and "fail" in msg)
                        if rec.mark_attempts >= (2 if permanent else 6):
                            rec.mark_pending = False
                            if log_callback:
                                log_callback(
                                    f"[!] iCloud note 标记放弃 ({addr}) attempts={rec.mark_attempts}: {exc}"
                                )
                        else:
                            if log_callback:
                                log_callback(
                                    f"[!] 后台写 iCloud note 失败 ({addr}) "
                                    f"#{rec.mark_attempts}, {delay:.0f}s后重试: {exc}"
                                )
                    self._dump_records(data, records)
                    self._save_unlocked(data, conn)
            except Exception:
                if log_callback:
                    log_callback(f"[!] 后台写 iCloud note 失败 ({addr}): {exc}")
            return False

    def ensure_capacity(self, *, log_callback: LogFn = None) -> Dict[str, int]:
        """Ensure free aliases are around low/high watermarks. May sync/create."""
        log = log_callback or self._bg_log
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            self._expire_leases(records)
            counts = self._counts(records)
            self._dump_records(data, records)
            self._save_unlocked(data, conn)
        free = int(counts.get("free") or 0)
        if free >= self.low_watermark:
            # The background loop uses this timestamp to rate-limit inventory
            # checks. Without it, a healthy inventory is rewritten every 0.5s.
            self._last_replenish_at = _now()
            return counts

        # replenish via sync first
        if self.reuse_aliases:
            try:
                counts = self._sync_from_apple(log_callback=log)
                free = int(counts.get("free") or 0)
            except Exception as exc:
                if log:
                    log(f"[!] 低水位同步失败: {exc}")

        if free >= self.low_watermark or not self.create_when_exhausted:
            self._last_replenish_at = _now()
            return counts

        need = min(self.create_per_cycle, max(self.high_watermark - free, 0))
        if need <= 0:
            self._last_replenish_at = _now()
            return counts
        if log:
            log(f"[*] iCloud 低水位补货: free={free} < {self.low_watermark}, 新建 {need} 个")
        for _ in range(need):
            try:
                created = self._create_remote_alias(log_callback=log)
                with self._tx() as conn:
                    data = self._load_unlocked(conn)
                    records = self._records(data)
                    # keep created as free inventory (already platform-tagged if cloud_mark)
                    created.state = STATE_FREE
                    created.mark_pending = False
                    records[created.email] = created
                    self._dump_records(data, records)
                    self._save_unlocked(data, conn)
                    counts = self._counts(records)
            except Exception as exc:
                try:
                    with self._tx() as conn:
                        data = self._load_unlocked(conn)
                        self._metric_add(data, "create_fail")
                        self._save_unlocked(data, conn)
                except Exception:
                    pass
                if log:
                    log(f"[!] 低水位新建失败: {exc}")
                break
        self._last_replenish_at = _now()
        return counts

    def _background_loop(self) -> None:
        while not self._bg_stop.is_set():
            # 1) mark queue with short wait
            try:
                email = self._mark_q.get(timeout=0.5)
            except queue.Empty:
                email = ""
            if email:
                self._process_mark_email(email, log_callback=self._bg_log)

            # 2) opportunistic pending scan
            if self.async_mark and self.cloud_mark:
                pending = self._next_mark_pending_email()
                if pending:
                    self._process_mark_email(pending, log_callback=self._bg_log)

            # 3) low watermark replenish
            if self.background_replenish:
                due = (_now() - float(self._last_replenish_at or 0)) >= self.replenish_interval_sec
                if due:
                    try:
                        self.ensure_capacity(log_callback=self._bg_log)
                    except Exception as exc:
                        if self._bg_log:
                            self._bg_log(f"[!] 后台补货异常: {exc}")
                        self._last_replenish_at = _now()

    def list_aliases(self, limit: int = 200) -> List[Dict[str, Any]]:
        """Return a bounded local inventory snapshot without contacting Apple."""
        maximum = max(1, min(int(limit or 200), 500))
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            self._expire_leases(records)
            ordered = sorted(
                records.values(),
                key=lambda item: (float(item.last_seen_at or 0), str(item.email or "")),
                reverse=True,
            )
            return [record.to_dict() for record in ordered[:maximum]]

    def stats(self) -> Dict[str, Any]:
        with self._tx() as conn:
            data = self._load_unlocked(conn)
            records = self._records(data)
            self._expire_leases(records)
            counts = self._counts(records)
            pending = sum(1 for r in records.values() if r.mark_pending)
            metrics = data.get("metrics") if isinstance(data.get("metrics"), dict) else {}
            acquire_total = float(metrics.get("acquire_total") or 0)
            inv_hit = float(metrics.get("acquire_inventory_hit") or 0)
            sync_total = float(metrics.get("sync_total") or 0)
            sync_ms_total = float(metrics.get("sync_duration_ms_total") or 0)
            counts["last_full_sync_at"] = float(data.get("last_full_sync_at") or 0)
            counts["inventory_path"] = self._db_path()
            counts["inventory_backend"] = "sqlite"
            counts["mark_pending"] = pending
            counts["mark_queue"] = int(self._mark_q.qsize())
            counts["low_watermark"] = self.low_watermark
            counts["high_watermark"] = self.high_watermark
            counts["async_mark"] = bool(self.async_mark)
            counts["background_replenish"] = bool(self.background_replenish)
            counts["background_alive"] = bool(self._bg_thread and self._bg_thread.is_alive())
            counts["metrics"] = {k: float(metrics.get(k, 0) or 0) for k in METRIC_KEYS}
            counts["acquire_inventory_hit_rate"] = (inv_hit / acquire_total) if acquire_total else 0.0
            counts["sync_avg_ms"] = (sync_ms_total / sync_total) if sync_total else 0.0
            return counts


_service_mu = threading.Lock()
_services: Dict[str, AliasLeaseService] = {}


def get_lease_service(
    cookies_raw: str,
    *,
    inventory_path: str = "",
    platform: str = DEFAULT_PLATFORM,
    label: str = "chatgpt",
    lease_ttl_sec: float = DEFAULT_LEASE_TTL_SEC,
    sync_interval_sec: float = DEFAULT_SYNC_INTERVAL_SEC,
    reuse_aliases: bool = True,
    create_when_exhausted: bool = True,
    cloud_mark: bool = True,
    coordination_mode: str = "local_fast",
    async_mark: bool = True,
    background_replenish: bool = True,
    low_watermark: int = DEFAULT_LOW_WATERMARK,
    high_watermark: int = DEFAULT_HIGH_WATERMARK,
    replenish_interval_sec: float = DEFAULT_REPLENISH_INTERVAL_SEC,
    create_per_cycle: int = DEFAULT_CREATE_PER_CYCLE,
    fail_cooldown_sec: float = DEFAULT_FAIL_COOLDOWN_SEC,
    fail_cooldown_max_sec: float = DEFAULT_FAIL_COOLDOWN_MAX_SEC,
    fail_cooldown_threshold: int = DEFAULT_FAIL_COOLDOWN_THRESHOLD,
    timeout: float = 25.0,
    auto_start_background: bool = True,
) -> AliasLeaseService:
    inv = _resolve_path(inventory_path)
    plat = str(platform or DEFAULT_PLATFORM).strip().lower() or DEFAULT_PLATFORM
    mode = str(coordination_mode or "local_fast").strip().lower()
    key = (
        f"{inv}|{plat}|{mode}|{bool(cloud_mark)}|{bool(reuse_aliases)}|"
        f"{bool(create_when_exhausted)}|{bool(async_mark)}|{bool(background_replenish)}|"
        f"{int(low_watermark)}|{int(high_watermark)}"
    )
    with _service_mu:
        svc = _services.get(key)
        if svc is None or svc.cookies_raw != str(cookies_raw or "").strip():
            svc = AliasLeaseService(
                cookies_raw=cookies_raw,
                inventory_path=inv,
                platform=plat,
                label=label,
                lease_ttl_sec=lease_ttl_sec,
                sync_interval_sec=sync_interval_sec,
                reuse_aliases=reuse_aliases,
                create_when_exhausted=create_when_exhausted,
                cloud_mark=cloud_mark,
                coordination_mode=mode,
                async_mark=async_mark,
                background_replenish=background_replenish,
                low_watermark=low_watermark,
                high_watermark=high_watermark,
                replenish_interval_sec=replenish_interval_sec,
                create_per_cycle=create_per_cycle,
                fail_cooldown_sec=fail_cooldown_sec,
                fail_cooldown_max_sec=fail_cooldown_max_sec,
                fail_cooldown_threshold=fail_cooldown_threshold,
                timeout=timeout,
                auto_start_background=auto_start_background,
            )
            _services[key] = svc
        else:
            # keep live service cooldown knobs in sync with latest config
            svc.fail_cooldown_sec = max(float(fail_cooldown_sec or DEFAULT_FAIL_COOLDOWN_SEC), 1.0)
            svc.fail_cooldown_max_sec = max(
                float(fail_cooldown_max_sec or DEFAULT_FAIL_COOLDOWN_MAX_SEC),
                svc.fail_cooldown_sec,
            )
            svc.fail_cooldown_threshold = max(
                int(fail_cooldown_threshold or DEFAULT_FAIL_COOLDOWN_THRESHOLD), 1
            )
        return svc


def reset_services_for_tests() -> None:
    with _service_mu:
        for svc in list(_services.values()):
            try:
                svc.stop_background(flush_marks=False, timeout=0.2)
            except Exception:
                pass
        _services.clear()



def remember_hme_from_key(
    cookies_raw: str,
    email: str,
    from_key: str,
    *,
    inventory_path: str = "",
    platform: str = DEFAULT_PLATFORM,
) -> None:
    """Persist HME From-key learned from a matched verification mail."""
    email_n = _norm_email(email)
    key = str(from_key or "").strip().lower()
    if not email_n or not key or not str(cookies_raw or "").strip():
        return
    try:
        svc = get_lease_service(
            cookies_raw,
            inventory_path=inventory_path or DEFAULT_INVENTORY_FILE,
            platform=platform,
            auto_start_background=False,
            background_replenish=False,
            async_mark=False,
        )
        with svc._tx() as conn:
            data = svc._load_unlocked(conn)
            records = svc._records(data)
            rec = records.get(email_n) or AliasRecord(email=email_n)
            rec.hme_from_key = key
            records[email_n] = rec
            svc._dump_records(data, records)
            svc._save_unlocked(data, conn)
    except Exception:
        pass


def lookup_hme_from_key(
    cookies_raw: str,
    email: str,
    *,
    inventory_path: str = "",
    platform: str = DEFAULT_PLATFORM,
) -> str:
    email_n = _norm_email(email)
    if not email_n or not str(cookies_raw or "").strip():
        return ""
    try:
        svc = get_lease_service(
            cookies_raw,
            inventory_path=inventory_path or DEFAULT_INVENTORY_FILE,
            platform=platform,
            auto_start_background=False,
            background_replenish=False,
            async_mark=False,
        )
        with svc._tx() as conn:
            data = svc._load_unlocked(conn)
            records = svc._records(data)
            rec = records.get(email_n)
            return str(getattr(rec, "hme_from_key", "") or "").strip().lower() if rec else ""
    except Exception:
        return ""
