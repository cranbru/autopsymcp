
import glob
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Maps short MCP keys -> TSK internal type names.
ARTIFACT_TYPE_NAMES: Dict[str, str] = {
    "WEB_HISTORY":           "TSK_WEB_HISTORY",
    "WEB_DOWNLOAD":          "TSK_WEB_DOWNLOAD",
    "WEB_COOKIE":            "TSK_WEB_COOKIE",
    "WEB_SEARCH":            "TSK_WEB_SEARCH_QUERY",
    "WEB_BOOKMARK":          "TSK_WEB_BOOKMARK",
    "EMAIL":                 "TSK_EMAIL_MSG",
    "INSTALLED_PROG":        "TSK_INSTALLED_PROG",
    "DEVICE_ATTACHED":       "TSK_DEVICE_ATTACHED",
    "RECENT_OBJECT":         "TSK_RECENT_OBJECT",
    "CONTACT":               "TSK_CONTACT",
    "MESSAGE":               "TSK_MESSAGE",
    "CALL_LOG":              "TSK_CALLLOG",
    "CALENDAR":              "TSK_CALENDAR_ENTRY",
    "KEYWORD_HIT":           "TSK_KEYWORD_HIT",
    "HASH_HIT":              "TSK_HASHSET_HIT",
    "ENCRYPTION_DETECTED":   "TSK_ENCRYPTION_DETECTED",
    "ENCRYPTION_SUSPECTED":  "TSK_ENCRYPTION_SUSPECTED",
    "INTERESTING_FILE":      "TSK_INTERESTING_FILE_HIT",
    "INTERESTING_ITEM":      "TSK_INTERESTING_ITEM",
    "OS_INFO":               "TSK_OS_INFO",
    "WIFI_NETWORK":          "TSK_WIFI_NETWORK",
    "GPS_TRACK":             "TSK_GPS_TRACKPOINT",
    "USER_ACCOUNT":          "TSK_OS_ACCOUNT",
    "ACCOUNT":               "TSK_ACCOUNT",
    "SHELL_BAG":             "TSK_SHELLBAG",
    "METADATA":              "TSK_METADATA",
    "DATA_SOURCE_USAGE":     "TSK_DATA_SOURCE_USAGE",
}

ARTIFACT_TYPE_KEYS = ", ".join(ARTIFACT_TYPE_NAMES.keys())

# Timestamps above this (in seconds) are likely stored as milliseconds.
_MS_THRESHOLD = 10_000_000_000  # year 2286 in seconds — safe cutoff

# Default base directories to search for Autopsy cases.
# Covers all user profiles on Windows.
_DEFAULT_CASE_ROOTS: List[str] = [
    r"C:\Users\*\Documents",   # all users' Documents folders (glob pattern)
    r"C:\Cases",               # common forensic workstation convention
    r"D:\Cases",
]

# ─────────────────────────────────────────────────────────────────────────────
# Case path resolution  (NEW v2.1)
# ─────────────────────────────────────────────────────────────────────────────

def _find_case_db(case_name: str) -> str:
    """
    Auto-locate an Autopsy case .db file given only the case name.

    Search strategy (first match wins):
      1. C:\\Users\\*\\Documents\\<case_name>\\<case_name>.db
      2. C:\\Users\\*\\Documents\\<case_name>\\*.db  (handles renamed .db files)
      3. Additional roots in _DEFAULT_CASE_ROOTS
      4. Current working directory

    Args:
        case_name: The case folder name (e.g. "MyCase" or "Investigation_2024").

    Returns:
        Absolute path string to the .db file.

    Raises:
        FileNotFoundError: If no matching .db file is found anywhere.
    """
    candidates: List[Path] = []

    # Build search roots — expand glob patterns (e.g. C:\Users\*)
    roots: List[Path] = []
    for root_pattern in _DEFAULT_CASE_ROOTS:
        expanded = glob.glob(root_pattern)
        if expanded:
            roots.extend(Path(p) for p in expanded)
        else:
            # Pattern had no wildcard or nothing matched; try literal
            roots.append(Path(root_pattern))

    # Also add the current working directory as a fallback
    roots.append(Path.cwd())

    for root in roots:
        # Primary: <root>/<case_name>/<case_name>.db
        primary = root / case_name / f"{case_name}.db"
        if primary.exists():
            return str(primary.resolve())

        # Secondary: <root>/<case_name>/*.db  (any .db inside the case folder)
        case_dir = root / case_name
        if case_dir.is_dir():
            db_files = list(case_dir.glob("*.db"))
            candidates.extend(db_files)

    # Return the first valid candidate found
    for c in candidates:
        if c.exists():
            return str(c.resolve())

    # Build a helpful error message
    searched = [
        str(root / case_name)
        for root in roots
    ]
    raise FileNotFoundError(
        f"Could not find a .db file for case '{case_name}'.\n"
        f"Searched in:\n" +
        "\n".join(f"  • {p}" for p in searched) +
        "\n\nOptions:\n"
        "  1. Provide the full db_path instead of case_name.\n"
        "  2. Check the case name matches the folder exactly (case-sensitive on some systems).\n"
        "  3. Find the path in Autopsy → Case → Case Properties."
    )


def _list_all_cases() -> List[Dict[str, str]]:
    """
    Scan default case roots and return all Autopsy cases found.

    Returns:
        List of dicts with keys: case_name, db_path, case_dir.
    """
    found: List[Dict[str, str]] = []
    seen: set = set()

    roots: List[Path] = []
    for root_pattern in _DEFAULT_CASE_ROOTS:
        expanded = glob.glob(root_pattern)
        if expanded:
            roots.extend(Path(p) for p in expanded)
        else:
            roots.append(Path(root_pattern))

    for root in roots:
        if not root.exists():
            continue
        try:
            for case_dir in root.iterdir():
                if not case_dir.is_dir():
                    continue
                db_files = list(case_dir.glob("*.db"))
                for db_file in db_files:
                    key = str(db_file.resolve())
                    if key in seen:
                        continue
                    seen.add(key)
                    found.append({
                        "case_name": case_dir.name,
                        "db_path":   key,
                        "case_dir":  str(case_dir.resolve()),
                    })
        except PermissionError:
            continue

    return found


def _resolve_path(db_path: Optional[str], case_name: Optional[str]) -> str:
    """
    Return a concrete .db path from either db_path or case_name.
    Exactly one of the two must be provided (validated in each model).
    """
    if db_path:
        return db_path
    if case_name:
        return _find_case_db(case_name)
    raise ValueError("Provide either db_path or case_name.")


# ─────────────────────────────────────────────────────────────────────────────
# MCP Server
# ─────────────────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "autopsy_mcp",
    instructions=(
        "Autopsy digital forensics MCP v2.1. Reads Autopsy case SQLite databases "
        "directly — no plugins or API keys needed. "
        "You can identify a case by its full db_path OR just its case_name "
        "(the server will auto-locate the .db under C:\\Users\\*\\Documents\\). "
        "Start with autopsy_find_cases to list available cases, then "
        "autopsy_triage for a rapid overview, then drill down with other tools."
    ),
)

# ─────────────────────────────────────────────────────────────────────────────
# SQLite helpers  (all read-only)
# ─────────────────────────────────────────────────────────────────────────────

@contextmanager
def _open_db(db_path: str) -> Generator[sqlite3.Connection, None, None]:
    """
    Open the Autopsy SQLite DB read-only; guarantees the connection is closed
    even if the caller raises an exception.
    """
    p = Path(db_path)
    if not p.exists():
        raise FileNotFoundError(
            f"Database file not found: {db_path}\n"
            "Pass the full path to your Autopsy case .db file, or just the case_name.\n"
            "Find it in Autopsy -> Case -> Case Properties."
        )
    if p.suffix.lower() != ".db":
        raise ValueError(f"Expected a .db file, got '{p.suffix}'.")
    conn = sqlite3.connect(f"file:{p.resolve()}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def _q(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def _scalar(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Any:
    row = conn.execute(sql, params).fetchone()
    return row[0] if row else None


def _fmt_ts(ts: Optional[int]) -> str:
    """
    Format a Unix timestamp to human-readable UTC.
    Autopsy occasionally stores timestamps in milliseconds; values above
    _MS_THRESHOLD are auto-divided by 1000 before formatting.
    """
    if ts is None or ts == 0:
        return "N/A"
    try:
        if ts > _MS_THRESHOLD:
            ts = ts // 1000
        return datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, OverflowError, ValueError):
        return str(ts)


def _attr_type_map(conn: sqlite3.Connection) -> Dict[int, str]:
    return {
        r["attribute_type_id"]: r["display_name"]
        for r in _q(conn, "SELECT attribute_type_id, display_name FROM blackboard_attribute_types")
    }


def _artifact_type_id(conn: sqlite3.Connection, tsk_name: str) -> Optional[int]:
    row = conn.execute(
        "SELECT artifact_type_id FROM blackboard_artifact_types WHERE type_name = ?",
        (tsk_name,),
    ).fetchone()
    return row["artifact_type_id"] if row else None


def _extract_attr_value(attr: Dict[str, Any]) -> Any:
    """
    Return the first non-None value across the four value columns.
    Explicit None checks prevent silently dropping legitimate 0 values
    (port 0, boolean False, zero-byte file size, etc.).
    """
    for col in ("value_text", "value_int64", "value_int32", "value_double"):
        v = attr.get(col)
        if v is not None:
            return v
    return None


def _fetch_artifacts(
    conn: sqlite3.Connection,
    type_id: int,
    limit: int,
    offset: int,
) -> List[Dict[str, Any]]:
    attr_map = _attr_type_map(conn)

    rows = _q(conn, """
        SELECT ba.artifact_id, ba.obj_id,
               COALESCE(tf.parent_path, '') || COALESCE(tf.name, '') AS source_path
        FROM   blackboard_artifacts ba
        LEFT JOIN tsk_files tf ON tf.obj_id = ba.obj_id
        WHERE  ba.artifact_type_id = ?
        ORDER  BY ba.artifact_id
        LIMIT ? OFFSET ?
    """, (type_id, limit, offset))

    for art in rows:
        raw = _q(conn, """
            SELECT attribute_type_id,
                   value_text, value_int32, value_int64, value_double
            FROM   blackboard_attributes
            WHERE  artifact_id = ?
        """, (art["artifact_id"],))

        art["attributes"] = {
            attr_map.get(a["attribute_type_id"], str(a["attribute_type_id"])): _extract_attr_value(a)
            for a in raw
            if _extract_attr_value(a) is not None
        }
    return rows


def _pagination_block(total: int, offset: int, returned: int) -> str:
    """Return a consistent pagination summary line."""
    end = offset + returned
    has_more = total > end
    page_info = f"Showing {offset + 1}–{end} of {total:,}"
    if has_more:
        page_info += f" | next page: offset={end}"
    return page_info


# ─────────────────────────────────────────────────────────────────────────────
# Input models  (v2.1: all support case_name OR db_path)
# ─────────────────────────────────────────────────────────────────────────────

class ResponseFormat(str, Enum):
    MARKDOWN = "markdown"
    JSON     = "json"


class _CaseLocator(BaseModel):
    """
    Mixin that lets every tool accept EITHER:
      - db_path   — full absolute path to the .db file (original behaviour)
      - case_name — just the case folder name; path is auto-resolved

    Exactly one must be provided. The resolved path is available via the
    `resolved_db_path` property after validation.
    """
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    db_path:   Optional[str] = Field(
        default=None,
        description=(
            "Full absolute path to the Autopsy case .db file. "
            "Provide this OR case_name, not both."
        ),
    )
    case_name: Optional[str] = Field(
        default=None,
        description=(
            "Case folder name only (e.g. 'MyCase'). "
            "The server will find the .db under C:\\Users\\*\\Documents\\<case_name>\\. "
            "Provide this OR db_path, not both."
        ),
    )
    response_format: ResponseFormat = Field(default=ResponseFormat.MARKDOWN)

    @model_validator(mode="after")
    def _check_exactly_one(self) -> "_CaseLocator":
        has_path = bool(self.db_path)
        has_name = bool(self.case_name)
        if has_path and has_name:
            raise ValueError("Provide db_path OR case_name, not both.")
        if not has_path and not has_name:
            raise ValueError("Provide either db_path (full path) or case_name (case folder name).")
        return self

    @property
    def resolved_db_path(self) -> str:
        """Resolve and return the concrete .db path."""
        return _resolve_path(self.db_path, self.case_name)


class DbInput(_CaseLocator):
    pass


class ArtifactInput(_CaseLocator):
    artifact_type: str = Field(..., description=f"Artifact type key. Supported: {ARTIFACT_TYPE_KEYS}")
    limit:  int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0,  ge=0)

    @field_validator("artifact_type")
    @classmethod
    def check_type(cls, v: str) -> str:
        v = v.upper()
        if v not in ARTIFACT_TYPE_NAMES:
            raise ValueError(f"Unknown type '{v}'. Valid: {ARTIFACT_TYPE_KEYS}")
        return v


class FileSearchInput(_CaseLocator):
    query:     str           = Field(..., description="SQL LIKE pattern for filename or path. Use % as wildcard e.g. '%.exe', '%password%'")
    mime_type: Optional[str] = Field(default=None, description="Filter by MIME type e.g. 'image/jpeg', 'application/x-msdownload'")
    limit:    int            = Field(default=50, ge=1, le=500)
    offset:   int            = Field(default=0,  ge=0)
    min_size: Optional[int]  = Field(default=None, ge=0, description="Min file size in bytes")
    max_size: Optional[int]  = Field(default=None, ge=0, description="Max file size in bytes")


class TimelineInput(_CaseLocator):
    start_unix:  Optional[int] = Field(default=None, description="Start time as Unix epoch seconds")
    end_unix:    Optional[int] = Field(default=None, description="End time as Unix epoch seconds")
    event_type:  Optional[str] = Field(default=None, description="Filter by event type display name, e.g. 'File Modified', 'Web Activity'")
    limit:       int           = Field(default=200, ge=1, le=2000)


class MultiArtifactInput(_CaseLocator):
    artifact_types:  List[str] = Field(..., description=f"2-6 artifact type keys. Supported: {ARTIFACT_TYPE_KEYS}", min_length=2, max_length=6)
    sample_per_type: int       = Field(default=30, ge=1, le=150, description="Artifacts per type (default 30)")

    @field_validator("artifact_types")
    @classmethod
    def check_types(cls, v: List[str]) -> List[str]:
        out = []
        for t in v:
            t = t.upper()
            if t not in ARTIFACT_TYPE_NAMES:
                raise ValueError(f"Unknown type '{t}'. Valid: {ARTIFACT_TYPE_KEYS}")
            out.append(t)
        return out


class KeywordHitInput(_CaseLocator):
    keyword:  Optional[str] = Field(default=None, description="Filter hits whose keyword contains this string (case-insensitive)")
    limit:    int           = Field(default=50, ge=1, le=500)
    offset:   int           = Field(default=0,  ge=0)


class FileMetadataInput(_CaseLocator):
    obj_id: int = Field(..., description="The file's obj_id from tsk_files (use autopsy_search_files to find it)")


# ─────────────────────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────────────────────

@mcp.tool(name="autopsy_find_cases", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_find_cases(params: ResponseFormat = ResponseFormat.MARKDOWN) -> str:
    """
    NEW v2.1 — Scan the system for all Autopsy cases and list them.

    Searches C:\\Users\\*\\Documents\\ (all user profiles) and common
    forensic roots (C:\\Cases, D:\\Cases). No parameters required.

    Returns:
        List of discovered cases with case name and .db path.
        Use the case_name value in any other tool to open that case automatically.
    """
    try:
        cases = _list_all_cases()

        if isinstance(params, str):
            fmt = ResponseFormat(params)
        else:
            fmt = params

        if fmt == ResponseFormat.JSON:
            return json.dumps({"cases": cases, "total": len(cases)}, indent=2)

        if not cases:
            return (
                "## No Autopsy Cases Found\n\n"
                "Searched in:\n" +
                "\n".join(f"- `{p}`" for p in _DEFAULT_CASE_ROOTS) +
                "\n\nIf your cases are elsewhere, use `db_path` with the full path instead."
            )

        lines = [
            f"## Autopsy Cases Found — {len(cases)} case(s)\n",
            "| Case Name | .db Path |",
            "|---|---|",
        ]
        for c in cases:
            lines.append(f"| `{c['case_name']}` | `{c['db_path']}` |")

        lines.append(
            "\n> **Tip**: Pass the **Case Name** as `case_name` in any tool "
            "and the server will find the .db automatically."
        )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_triage", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_triage(params: DbInput) -> str:
    """
    One-shot rapid triage: case metadata + artifact type counts +
    examiner tags in a single call. Use this first to orient yourself before
    calling more specific tools.

    Args:
        params.case_name: Just the case folder name e.g. 'MyCase' (auto-resolves path).
        params.db_path:   OR full path to the .db file (either one, not both).

    Returns:
        Case summary, data source list, artifact counts, and tagged items.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            meta: Dict[str, Any] = {}
            for tbl in ("tsk_db_info", "case_db_info"):
                try:
                    rows = _q(conn, f"SELECT * FROM {tbl}")
                    if rows:
                        meta.update(rows[0])
                except sqlite3.OperationalError:
                    pass

            try:
                sources = _q(conn, "SELECT * FROM data_source_info")
            except sqlite3.OperationalError:
                sources = []

            artifact_rows = _q(conn, """
                SELECT bat.type_name, bat.display_name,
                       COUNT(ba.artifact_id) AS count
                FROM   blackboard_artifact_types bat
                LEFT JOIN blackboard_artifacts ba
                       ON ba.artifact_type_id = bat.artifact_type_id
                GROUP  BY bat.artifact_type_id
                HAVING count > 0
                ORDER  BY count DESC
            """)
            total_artifacts = sum(r["count"] for r in artifact_rows)

            try:
                tagged_files = _scalar(conn, "SELECT COUNT(*) FROM content_tags") or 0
                tagged_arts  = _scalar(conn, "SELECT COUNT(*) FROM artifact_tags") or 0
            except sqlite3.OperationalError:
                tagged_files = tagged_arts = 0

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({
                "resolved_db_path": db_path,
                "meta": meta,
                "data_sources": sources,
                "artifact_types": artifact_rows,
                "total_artifacts": total_artifacts,
                "tagged_files": tagged_files,
                "tagged_artifacts": tagged_arts,
            }, indent=2, default=str)

        lines = [f"# Autopsy Triage — `{db_path}`\n"]

        if meta:
            lines.append("## Database")
            for k, v in meta.items():
                if v is not None:
                    lines.append(f"- **{k}**: {v}")

        lines.append(f"\n## Data Sources ({len(sources)})")
        for s in sources:
            lines.append(
                f"- **{s.get('name', 'N/A')}** | "
                f"Type: {s.get('type', 'N/A')} | "
                f"Added: {_fmt_ts(s.get('added_date_time') or s.get('date_added'))}"
            )
        if not sources:
            lines.append("_No data sources found — add one in Autopsy and re-run ingest._")

        lines.append(f"\n## Artifact Types — {len(artifact_rows)} types, {total_artifacts:,} total\n")
        lines.append("| MCP Key | Display Name | Count |")
        lines.append("|---|---|---:|")
        for r in artifact_rows:
            tsk = r["type_name"]
            key = next((k for k, v in ARTIFACT_TYPE_NAMES.items() if v == tsk), "—")
            lines.append(f"| `{key}` | {r['display_name']} | {r['count']:,} |")

        lines.append(f"\n## Examiner Tags")
        lines.append(f"- Tagged files: **{tagged_files:,}**")
        lines.append(f"- Tagged artifacts: **{tagged_arts:,}**")

        lines.append("\n> **Next steps**: use `autopsy_get_artifacts`, `autopsy_get_keyword_hits`, or `autopsy_search_files` to drill down.")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_case_info", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_case_info(params: DbInput) -> str:
    """Read case metadata, data sources, disk image info, filesystem details,
    and ingest module history from an Autopsy .db file.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.

    Returns:
        Case metadata, data source list, disk image details, filesystem info,
        and a log of which ingest modules were run and their status.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            meta: Dict[str, Any] = {}
            for tbl in ("tsk_db_info", "case_db_info"):
                try:
                    rows = _q(conn, f"SELECT * FROM {tbl}")
                    if rows:
                        meta[tbl] = rows
                except sqlite3.OperationalError:
                    pass

            try:
                sources = _q(conn, "SELECT * FROM data_source_info")
            except sqlite3.OperationalError:
                sources = []

            try:
                images = _q(conn, "SELECT * FROM tsk_image_info")
            except sqlite3.OperationalError:
                images = []

            try:
                fs_info = _q(conn, "SELECT * FROM tsk_fs_info")
            except sqlite3.OperationalError:
                fs_info = []

            try:
                ingest = _q(conn, """
                    SELECT imt.display_name, ij.start_date_time,
                           ij.end_date_time, ij.status
                    FROM   ingest_jobs ij
                    JOIN   ingest_module_types imt
                           ON imt.module_type_id = ij.ingest_module_type_id
                    ORDER  BY ij.start_date_time DESC
                """)
            except sqlite3.OperationalError:
                ingest = []

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {"resolved_db_path": db_path, "meta": meta, "data_sources": sources,
                 "images": images, "fs_info": fs_info, "ingest_jobs": ingest},
                indent=2, default=str,
            )

        lines = [f"## Autopsy Case: `{db_path}`\n"]

        if meta:
            lines.append("### Database Info")
            for tbl, rows in meta.items():
                for r in rows:
                    for k, v in r.items():
                        if v is not None:
                            lines.append(f"- **{k}**: {v}")

        lines.append(f"\n### Data Sources ({len(sources)})")
        for s in sources:
            lines.append(
                f"- **{s.get('name', 'N/A')}** | "
                f"Type: {s.get('type', 'N/A')} | "
                f"Added: {_fmt_ts(s.get('added_date_time') or s.get('date_added'))}"
            )

        if images:
            lines.append(f"\n### Disk Images ({len(images)})")
            for img in images:
                lines.append(
                    f"- obj_id={img.get('obj_id')} | "
                    f"Type: {img.get('type', 'N/A')} | "
                    f"Sector size: {img.get('ssize', 'N/A')} | "
                    f"Timezone: {img.get('tzone', 'N/A')}"
                )

        if fs_info:
            lines.append(f"\n### Filesystems ({len(fs_info)})")
            for f in fs_info:
                lines.append(
                    f"- obj_id={f.get('obj_id')} | "
                    f"FS type: {f.get('fs_type', 'N/A')} | "
                    f"Block size: {f.get('block_size', 'N/A')}"
                )

        if ingest:
            lines.append(f"\n### Ingest Modules Run ({len(ingest)})")
            for j in ingest:
                lines.append(
                    f"- **{j.get('display_name', 'N/A')}** | "
                    f"{j.get('status', 'N/A')} | "
                    f"{_fmt_ts(j.get('start_date_time'))} → {_fmt_ts(j.get('end_date_time'))}"
                )
        else:
            lines.append("\n### Ingest Modules\n_No ingest history found. Run Ingest -> Run Ingest Modules in Autopsy._")

        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_list_artifact_types", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_list_artifact_types(params: DbInput) -> str:
    """List every artifact type that has at least one artifact in this case,
    with counts. Run this before querying artifacts to see what evidence exists.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.

    Returns:
        Table of MCP key, TSK type name, display name, and count for each
        populated artifact type, sorted by count descending.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            rows = _q(conn, """
                SELECT bat.type_name, bat.display_name,
                       COUNT(ba.artifact_id) AS count
                FROM   blackboard_artifact_types bat
                LEFT JOIN blackboard_artifacts ba
                       ON ba.artifact_type_id = bat.artifact_type_id
                GROUP  BY bat.artifact_type_id
                HAVING count > 0
                ORDER  BY count DESC
            """)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(rows, indent=2)

        if not rows:
            return (
                "No artifacts found in this case.\n"
                "Make sure ingest modules have been run in Autopsy: "
                "Ingest -> Run Ingest Modules."
            )

        total_artifacts = sum(r["count"] for r in rows)
        lines = [
            f"## Artifact Types Present — {len(rows)} types, {total_artifacts:,} total artifacts\n",
            "| MCP Key | TSK Type Name | Display Name | Count |",
            "|---|---|---|---:|",
        ]
        for r in rows:
            tsk = r["type_name"]
            key = next((k for k, v in ARTIFACT_TYPE_NAMES.items() if v == tsk), "—")
            lines.append(f"| `{key}` | `{tsk}` | {r['display_name']} | {r['count']:,} |")

        lines.append("\n> Use the **MCP Key** as the `artifact_type` parameter in other tools.")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_get_artifacts", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_get_artifacts(params: ArtifactInput) -> str:
    """Retrieve artifacts of a specific type with all their attribute values
    (URLs, timestamps, email addresses, hash values, etc.).

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.artifact_type: Type key e.g. WEB_HISTORY, EMAIL, HASH_HIT.
        params.limit: Max rows to return (default 50, max 500).
        params.offset: Pagination offset.

    Returns:
        Each artifact with its source file path and all attribute name/value pairs.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            tsk_name = ARTIFACT_TYPE_NAMES[params.artifact_type]
            type_id  = _artifact_type_id(conn, tsk_name)

            if type_id is None:
                return (
                    f"Artifact type `{tsk_name}` not found in this case.\n"
                    "Use `autopsy_list_artifact_types` to see what is available."
                )

            total = _scalar(conn, "SELECT COUNT(*) FROM blackboard_artifacts WHERE artifact_type_id = ?", (type_id,))
            arts  = _fetch_artifacts(conn, type_id, params.limit, params.offset)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(
                {"total": total, "offset": params.offset, "artifacts": arts},
                indent=2, default=str,
            )

        lines = [
            f"## {params.artifact_type} Artifacts",
            _pagination_block(total, params.offset, len(arts)),
            "",
        ]
        for a in arts:
            attr_lines = [f"  - {k}: {v}" for k, v in a["attributes"].items() if v is not None]
            lines.append(f"### artifact_id={a['artifact_id']}")
            lines.append(f"- Source: `{a.get('source_path', 'N/A')}`")
            lines.extend(attr_lines if attr_lines else ["  - _(no attributes)_"])
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_get_keyword_hits", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_get_keyword_hits(params: KeywordHitInput) -> str:
    """
    Retrieve keyword hits with optional keyword filter.
    Much more useful than autopsy_get_artifacts for KEYWORD_HIT when there
    are hundreds of hits and you only care about a specific term.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.keyword: Optional substring to filter on (case-insensitive).
        params.limit / offset: Pagination.

    Returns:
        Keyword hits with matched term, source file, and surrounding context.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            type_id = _artifact_type_id(conn, "TSK_KEYWORD_HIT")
            if type_id is None:
                return "No keyword hits found. Was the Keyword Search ingest module run?"

            attr_map = _attr_type_map(conn)

            bind: List[Any] = [type_id]
            kw_filter = ""
            if params.keyword:
                kw_filter = """
                    AND ba.artifact_id IN (
                        SELECT artifact_id FROM blackboard_attributes
                        WHERE  value_text LIKE ? COLLATE NOCASE
                    )
                """
                bind.append(f"%{params.keyword}%")

            total = _scalar(conn, f"""
                SELECT COUNT(*) FROM blackboard_artifacts ba
                WHERE  ba.artifact_type_id = ? {kw_filter}
            """, tuple(bind))

            bind_page = bind + [params.limit, params.offset]
            rows = _q(conn, f"""
                SELECT ba.artifact_id, ba.obj_id,
                       COALESCE(tf.parent_path, '') || COALESCE(tf.name, '') AS source_path
                FROM   blackboard_artifacts ba
                LEFT JOIN tsk_files tf ON tf.obj_id = ba.obj_id
                WHERE  ba.artifact_type_id = ? {kw_filter}
                ORDER  BY ba.artifact_id
                LIMIT ? OFFSET ?
            """, tuple(bind_page))

            for art in rows:
                raw = _q(conn, """
                    SELECT attribute_type_id, value_text, value_int32, value_int64, value_double
                    FROM   blackboard_attributes WHERE artifact_id = ?
                """, (art["artifact_id"],))
                art["attributes"] = {
                    attr_map.get(a["attribute_type_id"], str(a["attribute_type_id"])): _extract_attr_value(a)
                    for a in raw if _extract_attr_value(a) is not None
                }

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"total": total, "offset": params.offset, "hits": rows}, indent=2, default=str)

        filter_label = f" matching '{params.keyword}'" if params.keyword else ""
        lines = [
            f"## Keyword Hits{filter_label}",
            _pagination_block(total, params.offset, len(rows)),
            "",
        ]
        for a in rows:
            attrs = a["attributes"]
            keyword  = attrs.get("Keyword", "N/A")
            preview  = attrs.get("Keyword Preview", attrs.get("Context", ""))
            lines.append(f"### `{keyword}` — `{a.get('source_path', 'N/A')}`")
            if preview:
                lines.append(f"> {preview}")
            for k, v in attrs.items():
                if k not in ("Keyword", "Keyword Preview", "Context") and v is not None:
                    lines.append(f"- {k}: {v}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_get_multiple_artifact_types", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_get_multiple_artifact_types(params: MultiArtifactInput) -> str:
    """Fetch a sample from several artifact types in a single call.
    Ideal for correlating evidence across categories.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.artifact_types: 2-6 type keys e.g. ["WEB_HISTORY", "EMAIL", "HASH_HIT"].
        params.sample_per_type: Artifacts per type to return (default 30, max 150).

    Returns:
        All requested artifact types with attributes, grouped by type.
    """
    try:
        db_path = params.resolved_db_path
        result: Dict[str, Any] = {}
        with _open_db(db_path) as conn:
            for atype in params.artifact_types:
                tsk_name = ARTIFACT_TYPE_NAMES[atype]
                type_id  = _artifact_type_id(conn, tsk_name)
                if type_id is None:
                    result[atype] = {"total": 0, "sampled": 0, "artifacts": [], "note": "type not found"}
                    continue
                total = _scalar(conn, "SELECT COUNT(*) FROM blackboard_artifacts WHERE artifact_type_id = ?", (type_id,))
                arts  = _fetch_artifacts(conn, type_id, params.sample_per_type, 0)
                result[atype] = {"total": total, "sampled": len(arts), "artifacts": arts}

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(result, indent=2, default=str)

        lines = ["## Multi-Type Artifact Sample\n"]
        for atype, data in result.items():
            note = f" _(note: {data['note']})_" if data.get("note") else ""
            lines.append(f"### {atype} — {data['sampled']} of {data['total']:,} total{note}")
            for a in data["artifacts"]:
                attr_str = " | ".join(f"{k}: {v}" for k, v in a["attributes"].items() if v is not None)
                lines.append(f"- `{a.get('source_path', '?')}` | {attr_str}")
            lines.append("")
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_search_files", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_search_files(params: FileSearchInput) -> str:
    """Search all files in the case by name or path using SQL LIKE patterns.
    % matches any sequence of characters, _ matches a single character.

    Examples: '%.exe', '%password%', 'NTUSER.DAT', '%Documents%resume%'

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.query: LIKE pattern for filename or path.
        params.mime_type: Optional MIME type filter e.g. 'image/jpeg'.
        params.min_size / max_size: Optional byte range filter.
        params.limit / offset: Pagination.

    Returns:
        Matching files with name, full path, size, timestamps, hashes, and MIME type.
    """
    try:
        db_path = params.resolved_db_path
        where = ["(tf.name LIKE ? OR tf.parent_path LIKE ?)"]
        bind: List[Any] = [params.query, params.query]

        if params.mime_type:
            where.append("tf.mime_type LIKE ?")
            bind.append(f"%{params.mime_type}%")
        if params.min_size is not None:
            where.append("tf.size >= ?")
            bind.append(params.min_size)
        if params.max_size is not None:
            where.append("tf.size <= ?")
            bind.append(params.max_size)

        w = " AND ".join(where)

        with _open_db(db_path) as conn:
            files = _q(conn, f"""
                SELECT tf.obj_id, tf.name, tf.parent_path, tf.size,
                       tf.crtime, tf.atime, tf.mtime, tf.ctime,
                       tf.md5, tf.sha256, tf.known, tf.mime_type,
                       tf.type AS file_type
                FROM   tsk_files tf
                WHERE  {w}
                ORDER  BY tf.parent_path, tf.name
                LIMIT ? OFFSET ?
            """, (*bind, params.limit, params.offset))

            total = _scalar(conn, f"SELECT COUNT(*) FROM tsk_files tf WHERE {w}", tuple(bind))

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"total": total, "files": files}, indent=2, default=str)

        lines = [
            f"## File Search: `{params.query}`",
            _pagination_block(total, params.offset, len(files)),
            "",
        ]
        for f in files:
            lines.append(
                f"### {f['name']} (obj_id={f['obj_id']})\n"
                f"- Path: `{f.get('parent_path', '')}{f['name']}`\n"
                f"- Size: {f.get('size') or 0:,} bytes"
                + (f" | MIME: `{f['mime_type']}`" if f.get("mime_type") else "") + "\n"
                f"- Created: {_fmt_ts(f.get('crtime'))} | "
                f"Modified: {_fmt_ts(f.get('mtime'))} | "
                f"Accessed: {_fmt_ts(f.get('atime'))}\n"
                f"- MD5: `{f.get('md5') or 'N/A'}` | SHA-256: `{f.get('sha256') or 'N/A'}`\n"
                f"- Known status: {f.get('known', 'N/A')}"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_get_timeline", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_get_timeline(params: TimelineInput) -> str:
    """Retrieve timeline events with optional Unix timestamp range and event type filter.

    Note: timeline_events is only populated after you open Autopsy's Timeline
    view (Tools -> Timeline) at least once.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.start_unix / end_unix: Unix epoch range (optional).
        params.event_type: Filter by event type name, e.g. 'File Modified'.
        params.limit: Max events to return (default 200, max 2000).

    Returns:
        Chronological events with timestamp, event type, and description.
    """
    try:
        db_path = params.resolved_db_path
        where: List[str] = []
        bind:  List[Any] = []

        if params.start_unix is not None:
            where.append("te.time >= ?")
            bind.append(params.start_unix)
        if params.end_unix is not None:
            where.append("te.time <= ?")
            bind.append(params.end_unix)
        if params.event_type:
            where.append("tet.display_name LIKE ? COLLATE NOCASE")
            bind.append(f"%{params.event_type}%")

        w = ("WHERE " + " AND ".join(where)) if where else ""

        with _open_db(db_path) as conn:
            if not params.event_type:
                try:
                    event_types = [
                        r["display_name"]
                        for r in _q(conn, "SELECT DISTINCT display_name FROM timeline_event_types ORDER BY display_name")
                    ]
                except sqlite3.OperationalError:
                    event_types = []
            else:
                event_types = []

            events = _q(conn, f"""
                SELECT te.time,
                       tet.display_name AS event_type,
                       te.description,
                       te.full_description
                FROM   timeline_events te
                LEFT JOIN timeline_event_types tet
                       ON tet.event_type_id = te.event_type_id
                {w}
                ORDER  BY te.time ASC
                LIMIT ?
            """, (*bind, params.limit))

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(events, indent=2, default=str)

        lines = [f"## Timeline Events — {len(events):,} shown\n"]
        if event_types:
            lines.append(f"**Available event types**: {', '.join(f'`{t}`' for t in event_types)}\n")
        for ev in events:
            desc = ev.get("full_description") or ev.get("description") or "N/A"
            lines.append(
                f"- **{_fmt_ts(ev.get('time'))}** | `{ev.get('event_type', 'N/A')}` | {desc}"
            )
        return "\n".join(lines)
    except sqlite3.OperationalError:
        return (
            "The `timeline_events` table does not exist yet.\n"
            "Open Autopsy -> Tools -> Timeline to populate it, then retry."
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_tagged_items", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_tagged_items(params: DbInput) -> str:
    """List all items the examiner has manually tagged in Autopsy,
    including tag names and comments.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.

    Returns:
        Tagged files and tagged artifacts with tag names and examiner comments.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            file_tags = _q(conn, """
                SELECT tn.display_name AS tag, ct.comment,
                       COALESCE(tf.parent_path, '') || COALESCE(tf.name, '') AS file_path
                FROM   content_tags ct
                JOIN   tsk_tag_names tn ON tn.tag_name_id = ct.tag_name_id
                LEFT JOIN tsk_files tf  ON tf.obj_id = ct.obj_id
                ORDER  BY tn.display_name
            """)

            art_tags = _q(conn, """
                SELECT tn.display_name AS tag, atr.comment,
                       bat.display_name AS artifact_type,
                       COALESCE(tf.parent_path, '') || COALESCE(tf.name, '') AS source_file
                FROM   artifact_tags atr
                JOIN   tsk_tag_names tn        ON tn.tag_name_id = atr.tag_name_id
                JOIN   blackboard_artifacts ba  ON ba.artifact_id = atr.artifact_id
                JOIN   blackboard_artifact_types bat ON bat.artifact_type_id = ba.artifact_type_id
                LEFT JOIN tsk_files tf          ON tf.obj_id = ba.obj_id
                ORDER  BY tn.display_name
            """)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps({"file_tags": file_tags, "artifact_tags": art_tags}, indent=2)

        lines = ["## Examiner-Tagged Items\n", f"### Tagged Files ({len(file_tags)})"]
        for t in file_tags:
            comment = f" — _{t['comment']}_" if t.get("comment") else ""
            lines.append(f"- 🏷 **{t['tag']}** | `{t.get('file_path', 'N/A')}`{comment}")
        if not file_tags:
            lines.append("_None_")

        lines.append(f"\n### Tagged Artifacts ({len(art_tags)})")
        for t in art_tags:
            comment = f" — _{t['comment']}_" if t.get("comment") else ""
            lines.append(
                f"- 🏷 **{t['tag']}** | `{t.get('artifact_type', 'N/A')}` | "
                f"`{t.get('source_file', 'N/A')}`{comment}"
            )
        if not art_tags:
            lines.append("_None_")

        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_hash_hits", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_hash_hits(params: DbInput) -> str:
    """Return all hash set hits in the case — files that matched a known hash
    set (malware, NSFW, or custom) during ingest.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.

    Returns:
        Each hit with source file path, hash set name, MD5, and SHA-256.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            type_id = _artifact_type_id(conn, "TSK_HASHSET_HIT")
            if type_id is None:
                return "No hash-set hits artifact type found. Was the Hash Lookup ingest module run?"
            arts = _fetch_artifacts(conn, type_id, 500, 0)

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(arts, indent=2, default=str)

        if not arts:
            return "No hash set hits in this case."

        lines = [f"## Hash Set Hits ({len(arts)} total)\n"]
        for a in arts:
            attr = a["attributes"]
            lines.append(
                f"- **{a.get('source_path', 'N/A')}**\n"
                f"  Set: `{attr.get('Hash Set Name', 'N/A')}` | "
                f"MD5: `{attr.get('MD5', 'N/A')}` | "
                f"SHA-256: `{attr.get('SHA-256', 'N/A')}`"
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error: {e}"


@mcp.tool(name="autopsy_file_metadata", annotations={"readOnlyHint": True, "destructiveHint": False})
async def autopsy_file_metadata(params: FileMetadataInput) -> str:
    """Get full metadata for a specific file by its Autopsy object ID.
    Use obj_id values from autopsy_search_files results.

    Args:
        params.case_name: Just the case folder name (auto-resolves path).
        params.db_path:   OR full path to the .db file.
        params.obj_id: The file's obj_id from tsk_files.

    Returns:
        All file metadata: timestamps, size, hashes, MIME type, and known status.
    """
    try:
        db_path = params.resolved_db_path
        with _open_db(db_path) as conn:
            rows = _q(conn, "SELECT * FROM tsk_files WHERE obj_id = ?", (params.obj_id,))

        if not rows:
            return f"No file found with obj_id={params.obj_id}."

        f = rows[0]

        if params.response_format == ResponseFormat.JSON:
            return json.dumps(dict(f), indent=2, default=str)

        return "\n".join([
            f"## File: {f.get('name', 'N/A')} (obj_id={params.obj_id})\n",
            f"- **Full path**: `{f.get('parent_path', '')}{f.get('name', '')}`",
            f"- **Size**: {(f.get('size') or 0):,} bytes",
            f"- **MIME type**: `{f.get('mime_type') or 'N/A'}`",
            f"- **Type**: {f.get('type', 'N/A')} | Dir type: {f.get('dir_type', 'N/A')}",
            f"- **Known**: {f.get('known', 'N/A')}",
            f"- **MD5**: `{f.get('md5') or 'N/A'}`",
            f"- **SHA-256**: `{f.get('sha256') or 'N/A'}`",
            f"- **Created**:  {_fmt_ts(f.get('crtime'))}",
            f"- **Modified**: {_fmt_ts(f.get('mtime'))}",
            f"- **Accessed**: {_fmt_ts(f.get('atime'))}",
            f"- **Changed**:  {_fmt_ts(f.get('ctime'))}",
            f"- **UID/GID**: {f.get('uid', 'N/A')} / {f.get('gid', 'N/A')}",
            f"- **Flags**: {f.get('flags', 'N/A')}",
        ])
    except Exception as e:
        return f"Error: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()