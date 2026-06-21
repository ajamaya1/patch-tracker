"""SQLite persistence for patches, CVEs and per-patch tracking state.

The store is intentionally simple: three tables and a handful of typed query
helpers. Re-ingesting a feed upserts patch/CVE rows but never clobbers a
user's tracking status -- the whole point of the tool is that triage state
survives refreshes.
"""

from __future__ import annotations

import datetime as _dt
import os
import sqlite3
from typing import Iterable, List, Optional

from .models import DEFAULT_STATUS, Cve, Patch

DEFAULT_DB_PATH = os.environ.get(
    "PATCH_TRACKER_DB",
    os.path.join(os.path.expanduser("~"), ".patch-tracker", "patches.db"),
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS patches (
    patch_id     TEXT PRIMARY KEY,
    source       TEXT NOT NULL,
    title        TEXT NOT NULL,
    product      TEXT,
    version      TEXT,
    release_date TEXT,
    url          TEXT,
    severity     TEXT,
    fetched_at   TEXT
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id             TEXT NOT NULL,
    patch_id           TEXT NOT NULL,
    source             TEXT NOT NULL,
    severity           TEXT,
    impact             TEXT,
    base_score         REAL,
    exploited          INTEGER NOT NULL DEFAULT 0,
    publicly_disclosed INTEGER NOT NULL DEFAULT 0,
    url                TEXT,
    first_seen         TEXT,
    PRIMARY KEY (cve_id, patch_id),
    FOREIGN KEY (patch_id) REFERENCES patches(patch_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS tracking (
    patch_id   TEXT PRIMARY KEY,
    status     TEXT NOT NULL,
    note       TEXT,
    updated_at TEXT,
    FOREIGN KEY (patch_id) REFERENCES patches(patch_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_exploited ON cves(exploited);
CREATE INDEX IF NOT EXISTS idx_cves_first_seen ON cves(first_seen);
CREATE INDEX IF NOT EXISTS idx_patches_source ON patches(source);
"""


def _today() -> str:
    return _dt.date.today().isoformat()


class Database:
    """Thin wrapper around a SQLite connection with the tracker's queries."""

    def __init__(self, path: str = DEFAULT_DB_PATH):
        self.path = path
        if path != ":memory:":
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    # -- lifecycle ---------------------------------------------------------
    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- writes ------------------------------------------------------------
    def upsert_patches(self, patches: Iterable[Patch]) -> int:
        """Insert or update patches and their CVEs.

        Returns the number of patches written. A default tracking row is
        created for any patch that does not already have one; existing
        tracking state is left untouched.
        """
        count = 0
        cur = self.conn.cursor()
        for patch in patches:
            cur.execute(
                """
                INSERT INTO patches
                    (patch_id, source, title, product, version,
                     release_date, url, severity, fetched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(patch_id) DO UPDATE SET
                    source=excluded.source,
                    title=excluded.title,
                    product=excluded.product,
                    version=excluded.version,
                    release_date=excluded.release_date,
                    url=excluded.url,
                    severity=excluded.severity,
                    fetched_at=excluded.fetched_at
                """,
                (
                    patch.patch_id, patch.source, patch.title, patch.product,
                    patch.version, patch.release_date, patch.url,
                    patch.severity, patch.fetched_at,
                ),
            )
            # Reconcile this patch's CVE set: drop CVEs no longer present,
            # upsert the rest. Crucially we never overwrite first_seen, so a
            # CVE keeps the date it was first ingested across daily refreshes.
            today = (patch.fetched_at or "")[:10] or _today()
            new_ids = [c.cve_id for c in patch.cves]
            if new_ids:
                placeholders = ",".join("?" * len(new_ids))
                cur.execute(
                    f"DELETE FROM cves WHERE patch_id = ? "
                    f"AND cve_id NOT IN ({placeholders})",
                    [patch.patch_id, *new_ids],
                )
            else:
                cur.execute(
                    "DELETE FROM cves WHERE patch_id = ?", (patch.patch_id,)
                )
            for cve in patch.cves:
                cur.execute(
                    """
                    INSERT INTO cves
                        (cve_id, patch_id, source, severity, impact,
                         base_score, exploited, publicly_disclosed, url,
                         first_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(cve_id, patch_id) DO UPDATE SET
                        source=excluded.source, severity=excluded.severity,
                        impact=excluded.impact, base_score=excluded.base_score,
                        exploited=excluded.exploited,
                        publicly_disclosed=excluded.publicly_disclosed,
                        url=excluded.url
                    """,
                    (
                        cve.cve_id, cve.patch_id, cve.source, cve.severity,
                        cve.impact, cve.base_score, int(cve.exploited),
                        int(cve.publicly_disclosed), cve.url,
                        cve.first_seen or today,
                    ),
                )
            cur.execute(
                """
                INSERT INTO tracking (patch_id, status, note, updated_at)
                VALUES (?, ?, NULL, ?)
                ON CONFLICT(patch_id) DO NOTHING
                """,
                (patch.patch_id, DEFAULT_STATUS, patch.fetched_at),
            )
            count += 1
        self.conn.commit()
        return count

    def set_status(
        self, patch_id: str, status: str, note: Optional[str], when: str
    ) -> bool:
        """Update tracking status for a patch. Returns False if unknown."""
        row = self.conn.execute(
            "SELECT 1 FROM patches WHERE patch_id = ?", (patch_id,)
        ).fetchone()
        if row is None:
            return False
        if note is None:
            self.conn.execute(
                """
                INSERT INTO tracking (patch_id, status, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(patch_id) DO UPDATE SET
                    status=excluded.status, updated_at=excluded.updated_at
                """,
                (patch_id, status, when),
            )
        else:
            self.conn.execute(
                """
                INSERT INTO tracking (patch_id, status, note, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(patch_id) DO UPDATE SET
                    status=excluded.status, note=excluded.note,
                    updated_at=excluded.updated_at
                """,
                (patch_id, status, note, when),
            )
        self.conn.commit()
        return True

    # -- reads -------------------------------------------------------------
    def list_patches(
        self,
        source: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        exploited_only: bool = False,
        since: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[sqlite3.Row]:
        """Return patch rows joined with tracking state and CVE counts."""
        sql = [
            """
            SELECT p.*, t.status, t.note, t.updated_at AS status_updated_at,
                   COUNT(c.cve_id) AS cve_count,
                   COALESCE(SUM(c.exploited), 0) AS exploited_count
            FROM patches p
            LEFT JOIN tracking t ON t.patch_id = p.patch_id
            LEFT JOIN cves c ON c.patch_id = p.patch_id
            """
        ]
        where: List[str] = []
        params: List[object] = []
        if source:
            where.append("p.source = ?")
            params.append(source)
        if status:
            where.append("t.status = ?")
            params.append(status)
        if severity:
            where.append("LOWER(p.severity) = ?")
            params.append(severity.lower())
        if since:
            where.append("p.release_date >= ?")
            params.append(since)
        if where:
            sql.append("WHERE " + " AND ".join(where))
        sql.append("GROUP BY p.patch_id")
        if exploited_only:
            sql.append("HAVING exploited_count > 0")
        sql.append("ORDER BY p.release_date DESC, p.patch_id")
        if limit:
            sql.append("LIMIT ?")
            params.append(limit)
        return self.conn.execute("\n".join(sql), params).fetchall()

    def get_patch(self, patch_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            """
            SELECT p.*, t.status, t.note, t.updated_at AS status_updated_at
            FROM patches p
            LEFT JOIN tracking t ON t.patch_id = p.patch_id
            WHERE p.patch_id = ?
            """,
            (patch_id,),
        ).fetchone()

    def get_cves_for_patch(self, patch_id: str) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM cves WHERE patch_id = ? ORDER BY cve_id",
            (patch_id,),
        ).fetchall()

    def list_cves(
        self,
        cve_id: Optional[str] = None,
        severity: Optional[str] = None,
        exploited_only: bool = False,
        source: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[sqlite3.Row]:
        """Return CVE rows joined to their patch's release date/title."""
        sql = [
            """
            SELECT c.*, p.title AS patch_title, p.release_date
            FROM cves c
            JOIN patches p ON p.patch_id = c.patch_id
            """
        ]
        where: List[str] = []
        params: List[object] = []
        if cve_id:
            where.append("c.cve_id = ?")
            params.append(cve_id.upper())
        if severity:
            where.append("LOWER(c.severity) = ?")
            params.append(severity.lower())
        if exploited_only:
            where.append("c.exploited = 1")
        if source:
            where.append("c.source = ?")
            params.append(source)
        if since:
            where.append("p.release_date >= ?")
            params.append(since)
        if where:
            sql.append("WHERE " + " AND ".join(where))
        sql.append("ORDER BY p.release_date DESC, c.cve_id")
        if limit:
            sql.append("LIMIT ?")
            params.append(limit)
        return self.conn.execute("\n".join(sql), params).fetchall()

    def count_new_cves(self, since: str) -> int:
        """Count distinct CVEs first seen on/after ``since`` (YYYY-MM-DD)."""
        return self.conn.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cves WHERE first_seen >= ?",
            (since,),
        ).fetchone()[0]

    def stats(self, new_since: Optional[str] = None) -> dict:
        """Return summary counts for the dashboard view.

        If ``new_since`` is given, include ``new_cves`` (CVEs first seen on or
        after that date).
        """
        c = self.conn
        total_patches = c.execute("SELECT COUNT(*) FROM patches").fetchone()[0]
        total_cves = c.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cves"
        ).fetchone()[0]
        exploited = c.execute(
            "SELECT COUNT(DISTINCT cve_id) FROM cves WHERE exploited = 1"
        ).fetchone()[0]
        by_source = {
            r["source"]: r["n"]
            for r in c.execute(
                "SELECT source, COUNT(*) AS n FROM patches GROUP BY source"
            )
        }
        by_status = {
            r["status"]: r["n"]
            for r in c.execute(
                "SELECT status, COUNT(*) AS n FROM tracking GROUP BY status"
            )
        }
        by_severity = {
            (r["severity"] or "unknown"): r["n"]
            for r in c.execute(
                "SELECT severity, COUNT(*) AS n FROM patches GROUP BY severity"
            )
        }
        result = {
            "total_patches": total_patches,
            "total_cves": total_cves,
            "exploited_cves": exploited,
            "by_source": by_source,
            "by_status": by_status,
            "by_severity": by_severity,
        }
        if new_since is not None:
            result["new_cves"] = self.count_new_cves(new_since)
        return result
