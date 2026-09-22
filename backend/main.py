from __future__ import annotations

import hashlib
import hmac
import math
import re
import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, UploadFile, File, Header, Form, Request
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "safeline.db"

app = FastAPI(title="SafeLine API", version="4.3.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

CATEGORIES = {
    "catcalling": "Catcalling",
    "following": "Following",
    "loitering_blocking": "Loitering / Blocking",
    "threatening": "Threatening behaviour",
    "unwanted_approach": "Unwanted approach",
    "other": "Other",
}
WHEN_OPTIONS = {"just_now": "Just now", "earlier_today": "Earlier today", "earlier": "Earlier"}

# Demo-safe abuse controls. These are intentionally in-memory so no client IP history is persisted.
_RATE_BUCKETS: dict[str, list[float]] = {}
_SUMMARY_CACHE = {"at": 0.0, "data": None}
TOKEN_SECRET_PATH = BASE_DIR / ".token_secret"
def get_token_secret() -> str:
    if TOKEN_SECRET_PATH.exists():
        return TOKEN_SECRET_PATH.read_text().strip()
    secret = uuid.uuid4().hex + uuid.uuid4().hex
    TOKEN_SECRET_PATH.write_text(secret)
    return secret
def enforce_rate_limit(key: str, limit: int, window_seconds: int) -> None:
    import time
    now_ts = time.time()
    values = [t for t in _RATE_BUCKETS.get(key, []) if now_ts - t < window_seconds]
    if len(values) >= limit:
        raise HTTPException(429, "Too many requests in a short period. Please wait and try again.")
    values.append(now_ts)
    _RATE_BUCKETS[key] = values

def client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"

def invalidate_summary_cache() -> None:
    _SUMMARY_CACHE["at"] = 0.0
    _SUMMARY_CACHE["data"] = None

def token_digest(raw_token: str) -> str:
    return hmac.new(get_token_secret().encode(), raw_token.encode(), hashlib.sha256).hexdigest()


class ReportCreate(BaseModel):
    spot_id: str | None = Field(default=None, max_length=50)
    category: str
    happened_when: Literal["just_now", "earlier_today", "earlier"]
    reporter_type: Literal["self", "witness"]
    still_happening: bool
    reporter_token: str = Field(min_length=20, max_length=120)
    note: str | None = Field(default=None, max_length=240)
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    location_label: str | None = Field(default=None, max_length=180)
    location_source: Literal["registered", "gps", "manual"] = "manual"
    location_consent: bool = False
    offline_queue_id: str | None = Field(default=None, max_length=80)


class ReportContextUpdate(BaseModel):
    reporter_token: str = Field(min_length=20, max_length=120)
    happened_when: Literal["just_now", "earlier_today", "earlier"]
    reporter_type: Literal["self", "witness"]
    still_happening: bool
    note: str | None = Field(default=None, max_length=240)


class ReportResponse(BaseModel):
    report_id: str
    spot_id: str | None
    spot_name: str
    category: str
    received_at: str
    status: str
    latitude: float | None = None
    longitude: float | None = None
    location_label: str
    location_source: str
    assigned_to: str | None = None
    assigned_authority: str | None = None


class StatusUpdate(BaseModel):
    status: Literal[
        "assigned", "acknowledged", "reviewing", "action_planned",
        "action_due", "completed", "monitoring", "reopened"
    ]
    action_type: str | None = Field(default=None, max_length=120)
    observation: str | None = Field(default=None, max_length=500)


class ContextEventCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    start_at: str
    end_at: str
    spot_id: str | None = Field(default=None, max_length=50)


class AuthorityLogin(BaseModel):
    police_id: str = Field(min_length=3, max_length=40)
    pin: str = Field(min_length=4, max_length=20)


class IntegrityReview(BaseModel):
    classification: Literal["normal_signal", "needs_verification", "duplicate", "coordinated_pattern", "insufficient_information"]
    note: str | None = Field(default=None, max_length=500)


class ActionEvidenceApproval(BaseModel):
    approved: bool
    note: str | None = Field(default=None, max_length=500)


class PlanningQuery(BaseModel):
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    radius_km: float = Field(default=1.5, ge=0.2, le=10)


class VerificationOutcome(BaseModel):
    outcome: Literal["pattern_confirmed", "pattern_not_confirmed", "insufficient_evidence", "context_explains", "reporting_integrity_concern"]
    note: str | None = Field(default=None, max_length=700)


class AttackLabScenario(BaseModel):
    scenario: Literal["genuine_slow_build", "coordinated_flood", "mixed_genuine_coordinated", "patient_spaced_flood", "one_reporter_repeat", "festival_event_spike", "cold_start", "cross_spot_corridor", "post_intervention", "adaptive_attacker"]
    volume: int = Field(default=24, ge=1, le=250)
    minutes: int = Field(default=120, ge=1, le=10080)
    reporter_diversity: int = Field(default=70, ge=5, le=100)
    location_spread: int = Field(default=20, ge=0, le=100)


def hash_pin(pin: str) -> str:
    salt = uuid.uuid4().hex
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 180_000).hex()
    return f"pbkdf2${salt}${digest}"


def verify_pin(pin: str, stored: str) -> bool:
    if stored.startswith("pbkdf2$"):
        try:
            _, salt, digest = stored.split("$", 2)
            actual = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt.encode(), 180_000).hex()
            return hmac.compare_digest(actual, digest)
        except ValueError:
            return False
    return hmac.compare_digest(pin, stored)


def json_compact(value) -> str:
    import json
    return json.dumps(value, separators=(",", ":"))


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now().isoformat()


def init_db() -> None:
    with closing(get_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS spots (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                venue_type TEXT NOT NULL,
                zone_name TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                spot_id TEXT,
                category TEXT NOT NULL,
                happened_when TEXT NOT NULL,
                reporter_type TEXT NOT NULL,
                still_happening INTEGER NOT NULL,
                reporter_token TEXT NOT NULL,
                note TEXT,
                received_at TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                location_label TEXT,
                location_source TEXT NOT NULL,
                location_consent INTEGER NOT NULL DEFAULT 0,
                location_key TEXT,
                event_weight REAL NOT NULL DEFAULT 1.0,
                client_queue_id TEXT,
                alert_id TEXT,
                assigned_to TEXT,
                FOREIGN KEY (spot_id) REFERENCES spots(id)
            );
            CREATE TABLE IF NOT EXISTS occurrences (
                id TEXT PRIMARY KEY,
                location_key TEXT,
                spot_id TEXT,
                category TEXT NOT NULL,
                started_at TEXT NOT NULL,
                last_report_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS occurrence_reports (
                occurrence_id TEXT NOT NULL,
                report_id TEXT NOT NULL UNIQUE,
                PRIMARY KEY (occurrence_id, report_id),
                FOREIGN KEY (occurrence_id) REFERENCES occurrences(id),
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                location_key TEXT NOT NULL,
                spot_id TEXT,
                location_label TEXT NOT NULL,
                latitude REAL,
                longitude REAL,
                tier TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'surfaced',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                assigned_to TEXT,
                action_type TEXT,
                observation TEXT
            );
            CREATE TABLE IF NOT EXISTS status_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT NOT NULL,
                old_status TEXT,
                new_status TEXT NOT NULL,
                changed_at TEXT NOT NULL,
                reason TEXT
            );
            CREATE TABLE IF NOT EXISTS context_events (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                start_at TEXT NOT NULL,
                end_at TEXT NOT NULL,
                location_key TEXT
            );
            CREATE TABLE IF NOT EXISTS assistance_requests (
                id TEXT PRIMARY KEY,
                report_id TEXT,
                latitude REAL,
                longitude REAL,
                location_label TEXT,
                created_at TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'requested',
                acknowledged_by TEXT,
                acknowledged_at TEXT
            );
            CREATE TABLE IF NOT EXISTS authority_users (
                police_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                station TEXT NOT NULL,
                role TEXT NOT NULL,
                pin TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS authority_branches (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, police_id TEXT NOT NULL, role TEXT NOT NULL,
                latitude REAL NOT NULL, longitude REAL NOT NULL, zone_name TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS authority_sessions (
                token TEXT PRIMARY KEY,
                police_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS report_reviews (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                classification TEXT NOT NULL,
                note TEXT,
                reviewed_by TEXT NOT NULL,
                reviewed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS action_evidence (
                id TEXT PRIMARY KEY,
                alert_id TEXT NOT NULL,
                filename TEXT NOT NULL,
                stored_path TEXT NOT NULL,
                mime_type TEXT,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                precheck_status TEXT NOT NULL,
                precheck_summary TEXT,
                action_type TEXT,
                supervisor_approved INTEGER NOT NULL DEFAULT 0,
                approved_at TEXT,
                approved_by TEXT,
                approval_note TEXT
            );
            """
        )
        # Upgrade older MVP databases safely.
        report_cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
        for name, ddl in [("acknowledged_by", "TEXT"), ("alert_id", "TEXT")]:
            if name not in report_cols:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {ddl}")
        assist_cols = {r[1] for r in conn.execute("PRAGMA table_info(assistance_requests)").fetchall()}
        for name, ddl in [("acknowledged_by", "TEXT"), ("acknowledged_at", "TEXT")]:
            if name not in assist_cols:
                conn.execute(f"ALTER TABLE assistance_requests ADD COLUMN {name} {ddl}")
        # Authority routing and report-analysis fields.
        spot_cols = {r[1] for r in conn.execute("PRAGMA table_info(spots)").fetchall()}
        for name, ddl in [("owner_police_id", "TEXT"), ("backup_police_id", "TEXT"), ("ack_deadline_minutes", "INTEGER NOT NULL DEFAULT 30")]:
            if name not in spot_cols:
                conn.execute(f"ALTER TABLE spots ADD COLUMN {name} {ddl}")
        alert_cols2 = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        if "ack_deadline_at" not in alert_cols2:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_deadline_at TEXT")
        if "escalated_at" not in alert_cols2:
            conn.execute("ALTER TABLE alerts ADD COLUMN escalated_at TEXT")
        evidence_cols = {r[1] for r in conn.execute("PRAGMA table_info(action_evidence)").fetchall()}
        if "action_type" not in evidence_cols:
            conn.execute("ALTER TABLE action_evidence ADD COLUMN action_type TEXT")
        context_cols = {r[1] for r in conn.execute("PRAGMA table_info(context_events)").fetchall()}
        if "location_key" not in context_cols:
            conn.execute("ALTER TABLE context_events ADD COLUMN location_key TEXT")
        review_cols = {r[1] for r in conn.execute("PRAGMA table_info(report_reviews)").fetchall()}
        if "verification_outcome" not in review_cols:
            conn.execute("ALTER TABLE report_reviews ADD COLUMN verification_outcome TEXT")
        conn.execute("""CREATE TABLE IF NOT EXISTS report_ai_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT NOT NULL, review_type TEXT NOT NULL,
            score REAL, flags TEXT, summary TEXT, created_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS concern_verifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, outcome TEXT NOT NULL,
            note TEXT, reviewed_by TEXT NOT NULL, reviewed_at TEXT NOT NULL
        )""")
        conn.execute("""CREATE TABLE IF NOT EXISTS trusted_contact_events (
            id TEXT PRIMARY KEY, event_type TEXT NOT NULL, contact_name TEXT NOT NULL,
            contact_phone TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL,
            delivery_state TEXT NOT NULL DEFAULT 'prepared'
        )""")
        get_token_secret()
        # Store only HMAC digests for reporter handles; never retain the client token itself.
        for rr in conn.execute("SELECT id,reporter_token FROM reports").fetchall():
            raw = rr["reporter_token"] or ""
            if not re.fullmatch(r"[0-9a-f]{64}", raw):
                conn.execute("UPDATE reports SET reporter_token=? WHERE id=?", (token_digest(raw), rr["id"]))
        conn.execute("INSERT OR IGNORE INTO authority_users(police_id,name,station,role,pin) VALUES(?,?,?,?,?)", ("POLICE-042", "Demo Duty Officer", "Malvan Authority · Malvan Taluka", "Duty Officer", ""))
        conn.execute("INSERT OR IGNORE INTO authority_users(police_id,name,station,role,pin) VALUES(?,?,?,?,?)", ("POLICE-099", "Demo Station Supervisor", "Malvan Authority · Malvan Taluka", "Station Supervisor", ""))
        for pid, demo_pin in (("POLICE-042", "1234"), ("POLICE-099", "5678")):
            user = conn.execute("SELECT pin FROM authority_users WHERE police_id=?", (pid,)).fetchone()
            if user and not str(user["pin"]).startswith("pbkdf2$"):
                conn.execute("UPDATE authority_users SET pin=? WHERE police_id=?", (hash_pin(demo_pin), pid))
        seed_demo_authority_branches(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}
        for name, ddl in [("location_key", "TEXT"), ("authority_status", "TEXT NOT NULL DEFAULT 'new'"), ("acknowledged_at", "TEXT"), ("event_weight", "REAL NOT NULL DEFAULT 1.0"), ("client_queue_id", "TEXT"), ("assigned_to", "TEXT")]:
            if name not in cols:
                conn.execute(f"ALTER TABLE reports ADD COLUMN {name} {ddl}")
        # Offline relay IDs are idempotency keys. Prevent a reconnect race from creating the same queued report twice.
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_reports_client_queue_id ON reports(client_queue_id) WHERE client_queue_id IS NOT NULL")
        # Legacy rows are considered new only when no authority acknowledgement exists.
        conn.execute("UPDATE reports SET authority_status='new' WHERE authority_status IS NULL OR authority_status=''")
        if "assigned_to" in {r[1] for r in conn.execute("PRAGMA table_info(reports)").fetchall()}:
            for rr in conn.execute("SELECT id,latitude,longitude FROM reports WHERE assigned_to IS NULL AND latitude IS NOT NULL AND longitude IS NOT NULL").fetchall():
                branch = nearest_authority_branch(conn, rr["latitude"], rr["longitude"])
                if branch: conn.execute("UPDATE reports SET assigned_to=? WHERE id=?", (branch[1]["police_id"], rr["id"]))
        cols = {r[1] for r in conn.execute("PRAGMA table_info(occurrences)").fetchall()}
        for name, ddl in [("location_key", "TEXT")]:
            if name not in cols:
                conn.execute(f"ALTER TABLE occurrences ADD COLUMN {name} {ddl}")
        # Existing alerts may use the previous shape. Rebuild only if required columns are missing.
        alert_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)").fetchall()}
        required = {"location_key", "location_label", "latitude", "longitude"}
        if not required.issubset(alert_cols):
            conn.execute("ALTER TABLE alerts RENAME TO alerts_legacy")
            conn.execute(
                """CREATE TABLE alerts (
                    id TEXT PRIMARY KEY, location_key TEXT NOT NULL, spot_id TEXT,
                    location_label TEXT NOT NULL, latitude REAL, longitude REAL,
                    tier TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'surfaced',
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
                    assigned_to TEXT, action_type TEXT, observation TEXT
                )"""
            )
            legacy_cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts_legacy)").fetchall()}
            if {"id", "spot_id", "tier", "status", "created_at", "updated_at"}.issubset(legacy_cols):
                for r in conn.execute("SELECT * FROM alerts_legacy").fetchall():
                    s = get_spot(conn, r["spot_id"])
                    if s:
                        conn.execute(
                            "INSERT OR IGNORE INTO alerts VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (r["id"], f"SPOT:{s['id']}", s["id"], s["name"], s["latitude"], s["longitude"], r["tier"], r["status"], r["created_at"], r["updated_at"], r["assigned_to"], r["action_type"], r["observation"]),
                        )
            conn.execute("DROP TABLE alerts_legacy")
        existing = conn.execute("SELECT COUNT(*) AS n FROM spots").fetchone()["n"]
        if existing == 0:
            conn.executemany(
                "INSERT INTO spots(id,name,venue_type,zone_name,latitude,longitude) VALUES(?,?,?,?,?,?)",
                [
                    ("SPOT-042", "University North Gate", "university_corridor", "North Gate Corridor", 18.5204, 73.8567),
                    ("SPOT-043", "North Gate Walkway", "university_corridor", "North Gate Corridor", 18.5211, 73.8571),
                    ("SPOT-051", "Civic Transit Gate", "market_gate", "Civic Zone", 18.5194, 73.8552),
                    ("SPOT-060", "Station Forecourt", "station", "Station Zone", 18.5230, 73.8590),
                ],
            )
        conn.execute("UPDATE spots SET name='Civic Transit Gate', zone_name='Civic Zone' WHERE id='SPOT-051'")
        conn.execute("UPDATE spots SET owner_police_id='POLICE-042', backup_police_id='POLICE-099', ack_deadline_minutes=30 WHERE owner_police_id IS NULL OR backup_police_id IS NULL")
        conn.execute("UPDATE reports SET location_label='Civic Transit Gate' WHERE spot_id='SPOT-051'")
        conn.execute("UPDATE alerts SET location_label='Civic Transit Gate' WHERE spot_id='SPOT-051'")
        # Backfill location keys for old reports.
        for r in conn.execute("SELECT id,spot_id,latitude,longitude,location_label FROM reports WHERE location_key IS NULL").fetchall():
            key = location_key(r["spot_id"], r["latitude"], r["longitude"], r["location_label"])
            conn.execute("UPDATE reports SET location_key=? WHERE id=?", (key, r["id"]))
        # Older databases did not associate reports with a case episode. Backfill
        # to the latest case for the location; newly created reports are always
        # attached to the exact alert returned by refresh_alert().
        for r in conn.execute("SELECT id,location_key FROM reports WHERE alert_id IS NULL").fetchall():
            a = latest_alert_for_location(conn, r["location_key"])
            if a:
                conn.execute("UPDATE reports SET alert_id=? WHERE id=?", (a["id"], r["id"]))
        conn.commit()


def get_spot(conn, spot_id: str | None):
    if not spot_id:
        return None
    return conn.execute("SELECT * FROM spots WHERE id=? AND active=1", (spot_id,)).fetchone()


def distance_m(lat1, lon1, lat2, lon2):
    if None in (lat1, lon1, lat2, lon2):
        return None
    r = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def nearest_authority_branch(conn, lat, lon):
    if lat is None or lon is None:
        return None
    ranked=[]
    for row in conn.execute("SELECT * FROM authority_branches WHERE active=1").fetchall():
        d=distance_m(lat,lon,row["latitude"],row["longitude"])
        if d is not None: ranked.append((d,row))
    ranked.sort(key=lambda x:x[0])
    return ranked[0] if ranked else None

def seed_demo_authority_branches(conn):
    branches=[
        ("BR-ACHRA","Malvan Authority · Malvan Taluka","POLICE-042","Duty Officer",16.19248,73.44498,"Achra / Malvan North"),
        ("BR-MALVAN","Malvan Authority · Malvan Taluka","POLICE-099","Station Supervisor",16.0558,73.4683,"Malvan"),
        ("BR-CHINDAR","Chindar Authority · Chindar Taluka","POLICE-042","Duty Officer",16.1165,73.5900,"Chindar Corridor"),
        ("BR-DEVGAD","Devgad Authority · Devgad Taluka","POLICE-099","Station Supervisor",16.3750,73.3830,"Devgad"),
    ]
    conn.executemany("INSERT OR REPLACE INTO authority_branches(id,name,police_id,role,latitude,longitude,zone_name,active) VALUES(?,?,?,?,?,?,?,1)",branches)


def nearest_spot(conn, lat, lon, max_m=250):
    if lat is None or lon is None:
        return None
    best = None
    for row in conn.execute("SELECT * FROM spots WHERE active=1").fetchall():
        d = distance_m(lat, lon, row["latitude"], row["longitude"])
        if d is not None and d <= max_m and (best is None or d < best[0]):
            best = (d, row)
    return best


def normalize_label(label: str | None) -> str:
    if not label:
        return "Unspecified public location"
    return re.sub(r"\s+", " ", label.strip())[:180]


def authority_name_from_location(label: str | None) -> str | None:
    """Use the broader locality in a location label for demo jurisdiction routing.

    Examples: ``Achra, Malvan`` -> ``Malvan Authority · Malvan Taluka`` and
    ``Andheri East, Mumbai`` -> ``Mumbai Authority``. State names are ignored
    when they are the only broader component.
    """
    clean = normalize_label(label)
    if not clean or clean.startswith("Unspecified"):
        return None
    parts = [re.sub(r"\s+", " ", p).strip() for p in re.split(r"[,·]", clean) if p.strip()]
    if len(parts) < 2:
        return None
    broader = parts[1]
    broader_l = broader.lower()
    if broader_l in {"maharashtra", "india", "goa", "karnataka", "gujarat"}:
        # A two-part label such as ``Devgad, Maharashtra`` still needs the
        # locality (Devgad), while ``Achra, Malvan, Maharashtra`` keeps
        # Malvan as the broader jurisdiction.
        broader = parts[2] if len(parts) >= 3 else parts[0]
        broader_l = broader.lower()
    if broader_l in {"malvan", "malvan taluka"}:
        return "Malvan Authority · Malvan Taluka"
    return f"{broader} Authority"


def location_key(spot_id, lat, lon, label):
    if spot_id:
        return f"SPOT:{spot_id}"
    if lat is not None and lon is not None:
        # Approx. 50–100 m cells. This groups nearby GPS reports without retaining a movement trail.
        return f"GEO:{round(lat, 3):.3f}:{round(lon, 3):.3f}"
    clean = re.sub(r"[^a-z0-9]+", "-", normalize_label(label).lower()).strip("-")
    return f"MANUAL:{clean[:80]}"


def occurrence_category_compatible(a, b):
    if a == b:
        return True
    related = {
        frozenset(("catcalling", "unwanted_approach")),
        frozenset(("following", "unwanted_approach")),
        frozenset(("loitering_blocking", "unwanted_approach")),
        frozenset(("threatening", "unwanted_approach")),
    }
    return frozenset((a, b)) in related


def assign_occurrence(conn, report_id, loc_key, spot_id, category, received_at):
    rows = conn.execute("SELECT * FROM occurrences WHERE location_key=? ORDER BY last_report_at DESC", (loc_key,)).fetchall()
    current = datetime.fromisoformat(received_at)
    target = None
    for row in rows:
        last = datetime.fromisoformat(row["last_report_at"])
        if (current - last).total_seconds() > 15 * 60:
            continue
        if not occurrence_category_compatible(row["category"], category):
            continue
        target = row
        break
    if target:
        oid = target["id"]
        conn.execute("UPDATE occurrences SET last_report_at=? WHERE id=?", (received_at, oid))
    else:
        oid = f"OCC-{uuid.uuid4().hex[:8].upper()}"
        conn.execute(
            "INSERT INTO occurrences(id,location_key,spot_id,category,started_at,last_report_at) VALUES(?,?,?,?,?,?)",
            (oid, loc_key, spot_id, category, received_at, received_at),
        )
    conn.execute("INSERT INTO occurrence_reports VALUES(?,?)", (oid, report_id))
    return oid


def get_location_rows(conn, loc_key):
    return conn.execute("SELECT * FROM reports WHERE location_key=? ORDER BY received_at", (loc_key,)).fetchall()


def score_votes(rows, occurrence_groups=None, token_lifetimes=None):
    """Occurrence-first influence model.

    A reporter can repeat, but repetition decays. Corroboration inside one occurrence
    helps a REVIEW decision without being allowed to manufacture independent episodes.
    Location grounding is taken from server-normalised rows, never from the client's claim.
    """
    if not rows:
        return {"effective_signal": 0.0, "raw_sources": 0, "source_mix": {}, "integrity_flags": [], "corroboration": 0.0}
    token_lifetimes = token_lifetimes or {}
    by_token = {}
    for r in rows:
        by_token.setdefault(r["reporter_token"], []).append(r)
    source_factor = {"registered": 1.0, "gps": 0.72, "manual": 0.45}
    token_signal = 0.0
    for tok, token_rows in by_token.items():
        token_rows = sorted(token_rows, key=lambda x: x["received_at"])
        contribution = 0.0
        # First observation carries the most influence; repeats decay and are capped.
        for idx, r in enumerate(token_rows[:8]):
            contribution += (0.62 * (0.42 ** idx)) * source_factor.get(r["location_source"], 0.45)
        token_signal += min(0.95, contribution)
    groups = occurrence_groups or [[r] for r in rows]
    episode_signal = 0.0
    max_occ_sources = 0
    corroborated_occurrences = 0
    for group in groups:
        unique = len({r["reporter_token"] for r in group})
        max_occ_sources = max(max_occ_sources, unique)
        if unique >= 3:
            corroborated_occurrences += 1
        # One episode has a hard cap. Extra witnesses add corroboration, not episodes.
        episode_signal += min(1.35, 0.75 + 0.15 * min(unique, 4))
    effective_signal = min(token_signal, episode_signal)
    distinct = len(by_token)
    stamps = sorted(datetime.fromisoformat(r["received_at"]) for r in rows)
    active_days = len({r["received_at"][:10] for r in rows})
    span_days = ((stamps[-1] - stamps[0]).total_seconds() / 86400) if len(stamps) > 1 else 0.0
    gaps = [(b-a).total_seconds()/60 for a,b in zip(stamps, stamps[1:])]
    flags=[]
    new_token_ratio = sum(1 for tok in by_token if token_lifetimes.get(tok, 1) <= 1) / max(1, distinct)
    repeated_tokens = sum(1 for tok, rs in by_token.items() if len(rs) > 1)
    if len(stamps) >= 6 and gaps:
        short_gap_share = sum(g <= 12 for g in gaps) / len(gaps)
        if short_gap_share > 0.75:
            flags.append("high temporal correlation")
    # Patient manipulation is based on concentration versus independent episodes, not a 2-day cutoff.
    if distinct >= 8 and new_token_ratio >= 0.8 and 0.75 <= span_days <= 4.5:
        flags.append("high first-seen source concentration over short horizon")
    elif distinct >= 5 and new_token_ratio >= 0.7 and span_days >= 0.75 and len(groups) <= max(2, math.ceil(distinct * 0.55)):
        flags.append("source concentration across few episodes")
    if repeated_tokens and repeated_tokens / max(1, distinct) >= 0.4:
        flags.append("repeated-source influence")
    if distinct >= 8 and new_token_ratio >= 0.8:
        flags.append("high share of first-seen reporting tokens")
    source_mix={}
    for r in rows:
        source_mix[r["location_source"]]=source_mix.get(r["location_source"],0)+1
    if source_mix.get("gps",0) > source_mix.get("registered",0) and source_mix.get("gps",0) >= 4:
        flags.append("mostly GPS-grounded signals")
        effective_signal *= 0.82

    # Report diversity is a separate anti-gaming dimension from distinct reporters
    # and distinct times. A natural pattern can contain several behaviour categories,
    # while a coordinated flood may concentrate heavily on one category. This is only
    # an integrity signal: it never labels reports as fake or proves coordination.
    category_mix={}
    for r in rows:
        category = (r["category"] or "other").strip().lower()
        category_mix[category] = category_mix.get(category, 0) + 1
    category_total = sum(category_mix.values())
    category_diversity = 0.0
    if category_total and len(category_mix) > 1:
        entropy = -sum((n / category_total) * math.log(n / category_total) for n in category_mix.values())
        category_diversity = entropy / math.log(len(category_mix))
    dominant_category_share = max(category_mix.values()) / max(1, category_total) if category_mix else 0.0
    if category_total >= 6 and (len(category_mix) == 1 or dominant_category_share >= 0.80):
        flags.append("low category diversity")
        effective_signal *= 0.88
    if "high first-seen source concentration over short horizon" in flags or "source concentration across few episodes" in flags:
        effective_signal *= 0.62
    if "repeated-source influence" in flags:
        effective_signal *= 0.78
    if "high share of first-seen reporting tokens" in flags:
        effective_signal *= 0.82
    corroboration = min(1.0, max_occ_sources / 5.0) if groups else 0.0
    return {"effective_signal": round(effective_signal,2), "raw_sources": distinct, "source_mix": source_mix, "category_mix": category_mix, "category_diversity": round(category_diversity,2), "dominant_category_share": round(dominant_category_share,2), "integrity_flags": flags, "corroboration": round(corroboration,2), "corroborated_occurrences": corroborated_occurrences}


def active_context_for(conn, rows):
    if not rows:
        return []
    location_keys = {r["location_key"] for r in rows}
    contexts = []
    for c in conn.execute("SELECT * FROM context_events").fetchall():
        try:
            if c["location_key"] and c["location_key"] not in location_keys:
                continue
            start, end = datetime.fromisoformat(c["start_at"]), datetime.fromisoformat(c["end_at"])
            overlap = [r for r in rows if start <= datetime.fromisoformat(r["received_at"]) <= end]
            if overlap:
                contexts.append({"id": c["id"], "name": c["name"], "reports": len(overlap), "location_key": c["location_key"]})
        except (ValueError, TypeError):
            continue
    return contexts


def concern_for(conn, loc_key):
    rows = get_location_rows(conn, loc_key)
    if not rows:
        return {"tier": "WATCH", "report_count": 0, "distinct_reporters": 0, "active_days": 0, "occurrence_count": 0, "recent_rate": 0, "baseline": 0, "trend": "stable", "why": [], "held_back": [], "effective_signal": 0, "integrity_flags": [], "context": []}
    occurrences = conn.execute("SELECT * FROM occurrences WHERE location_key=?", (loc_key,)).fetchall()
    raw_distinct = len({r["reporter_token"] for r in rows})
    days = len({r["received_at"][:10] for r in rows})
    occ = len(occurrences)
    recent_cut = now() - timedelta(days=14)
    recent = [r for r in rows if datetime.fromisoformat(r["received_at"]) >= recent_cut]
    prior = [r for r in rows if datetime.fromisoformat(r["received_at"]) < recent_cut]
    recent_rate = sum(float(r["event_weight"] or 1.0) for r in recent) / 2
    first = rows[0]
    spot = get_spot(conn, first["spot_id"])
    # Real weekly baseline: prior observations divided by the actual prior time span, not a fixed constant.
    if prior:
        prior_start = datetime.fromisoformat(prior[0]["received_at"])
        prior_end = datetime.fromisoformat(prior[-1]["received_at"])
        prior_weeks = max(1.0, (prior_end - prior_start).total_seconds() / (7 * 86400))
        prior_rate = len(prior) / prior_weeks
    else:
        prior_rate = 0.0
    venue_prior = 2.0 if spot and spot["venue_type"] == "market_gate" else 0.5
    n_weeks = max(0.0, (now() - datetime.fromisoformat(first["received_at"])).total_seconds() / (7 * 86400))
    n_weeks = min(12.0, n_weeks)
    w = n_weeks / (n_weeks + 4) if n_weeks else 0
    baseline = max(0.5, w * prior_rate + (1 - w) * venue_prior)
    recent_days = len({r["received_at"][:10] for r in recent})
    trend = "rising" if len(recent) > len(prior) and len(recent) >= 3 else ("stable" if len(recent) == len(prior) else ("falling" if len(recent) < len(prior) else "developing"))
    groups=[]
    for o in occurrences:
        ids=[x[0] for x in conn.execute("SELECT report_id FROM occurrence_reports WHERE occurrence_id=?",(o["id"],)).fetchall()]
        group=[r for r in rows if r["id"] in ids]
        if group: groups.append(group)
    lifetimes={r["reporter_token"]:conn.execute("SELECT COUNT(*) n FROM reports WHERE reporter_token=?",(r["reporter_token"],)).fetchone()["n"] for r in rows}
    influence = score_votes(rows, groups, lifetimes)
    # Human integrity reviews affect downstream interpretation, but never erase raw reports.
    review_rows = conn.execute("SELECT report_id,classification FROM report_reviews WHERE report_id IN (SELECT id FROM reports WHERE location_key=?) ORDER BY reviewed_at DESC", (loc_key,)).fetchall()
    integrity_reviews = sum(1 for x in review_rows if x["classification"] in {"coordinated_pattern", "duplicate", "needs_verification", "insufficient_information"})
    if integrity_reviews:
        influence["effective_signal"] = round(max(0.0, influence["effective_signal"] * max(0.55, 1 - 0.08 * integrity_reviews)), 2)
        influence["integrity_flags"] = list(dict.fromkeys(influence["integrity_flags"] + ["authority integrity review present"]))
    context = active_context_for(conn, rows)
    context_count = sum(x["reports"] for x in context)
    adjusted_recent = max(0.0, sum(float(r["event_weight"] or 1.0) for r in recent) - context_count * 0.65)
    deviation = adjusted_recent / 2 > baseline * 1.5
    effective = influence["effective_signal"]
    # Decision gates require recurrence and effective independent signal, not raw reporter count.
    integrity_flag = bool(influence["integrity_flags"])
    corroborated_now = influence.get("corroboration", 0) >= 0.8 and days <= 2 and occ <= 2
    pattern_flag = any(x in influence["integrity_flags"] for x in ("high temporal correlation", "high first-seen source concentration over short horizon", "source concentration across few episodes", "repeated-source influence", "mostly GPS-grounded signals", "low category diversity"))
    if pattern_flag and effective < 4.0:
        tier = "REPORTING-PATTERN REVIEW"
    elif raw_distinct >= 5 and days >= 4 and occ >= 4 and deviation and effective >= 4.0 and not integrity_flag:
        tier = "PRIORITY"
    elif (raw_distinct >= 3 and days >= 2 and occ >= 2 and deviation and effective >= 2.2) or (corroborated_now and not integrity_flag):
        tier = "REVIEW"
    else:
        tier = "WATCH"
    why = [f"{raw_distinct} distinct reporting sources ({effective:.1f} effective signal)", f"activity across {days} day{'s' if days != 1 else ''}", f"{occ} related occurrence{'s' if occ != 1 else ''}"]
    if deviation: why.append("recent activity is above the working baseline")
    if any(int(r["still_happening"] or 0) for r in recent): why.append("at least one recent report says the behaviour may still be happening")
    if trend == "rising": why.append("recent activity is trending upward")
    elif trend == "falling": why.append("recent activity is below the comparison period")
    if context: why.append("some activity overlaps a logged context event")
    if influence["integrity_flags"]: why.append(" · ".join(influence["integrity_flags"]))
    if integrity_reviews: why.append(f"{integrity_reviews} authority integrity review{'s' if integrity_reviews != 1 else ''} recorded")
    held = []
    if not deviation: held.append("baseline deviation threshold not met")
    if effective < 2.5: held.append("effective independent signal below review gate")
    if days < 2: held.append("recurrence across separate days not established")
    if integrity_flag: held.append("integrity review is required before treating the signal as independent evidence")
    if context: held.append("context event may explain part of the recent increase")
    return {"tier": tier, "report_count": len(rows), "distinct_reporters": raw_distinct, "active_days": days, "occurrence_count": occ, "recent_rate": round(recent_rate, 2), "baseline": round(baseline, 2), "trend": trend, "why": why, "held_back": held, "effective_signal": effective, "integrity_flags": influence["integrity_flags"], "context": context}


def effective_case_status(conn, alert_row):
    """Return the status the authority UI is allowed to treat as operational truth.

    Legacy databases may contain a stale completed/monitoring value from an older
    build. Those records remain intact, but the UI must not present them as completed
    unless verification and independently approved evidence exist.
    """
    raw = alert_row["status"]
    if raw not in {"completed", "monitoring"}:
        return raw
    verified = conn.execute("SELECT 1 FROM concern_verifications WHERE alert_id=? LIMIT 1", (alert_row["id"],)).fetchone()
    approved = conn.execute(
        "SELECT 1 FROM action_evidence WHERE alert_id=? AND supervisor_approved=1 AND approved_by IS NOT NULL AND approved_by<>uploaded_by LIMIT 1",
        (alert_row["id"],),
    ).fetchone()
    if verified and approved:
        return raw
    return "action_planned" if alert_row["action_type"] else "reviewing"


def latest_alert_for_location(conn, loc_key):
    return conn.execute(
        "SELECT * FROM alerts WHERE location_key=? ORDER BY created_at DESC, rowid DESC LIMIT 1",
        (loc_key,),
    ).fetchone()


def refresh_alert(conn, loc_key):
    rows = get_location_rows(conn, loc_key)
    if not rows:
        return None
    c = concern_for(conn, loc_key)
    latest = rows[-1]
    stamp = iso_now()
    existing = latest_alert_for_location(conn, loc_key)
    spot = get_spot(conn, latest["spot_id"])
    should_route = c["tier"] in {"REVIEW", "PRIORITY", "REPORTING-PATTERN REVIEW"}

    # A completed case is an episode, not a permanent container for every future
    # report at the same location. A later report starts a fresh case episode so
    # verification, action notes and evidence cannot leak into the new case.
    if existing and existing["status"] in {"completed", "monitoring"}:
        try:
            case_updated = datetime.fromisoformat(existing["updated_at"])
            latest_received = datetime.fromisoformat(latest["received_at"])
        except (TypeError, ValueError):
            case_updated = None
            latest_received = None
        # Completed episodes always start a fresh case when a later report arrives.
        # A monitoring episode remains open only when its completion prerequisites
        # are actually satisfied; stale legacy monitoring states are isolated too.
        valid_status = effective_case_status(conn, existing)
        if latest_received and case_updated and latest_received > case_updated:
            if existing["status"] == "completed" or valid_status != "monitoring":
                existing = None

    if existing:
        old_status = existing["status"]
        new_status = old_status
        if old_status == "monitoring" and c["tier"] in {"REVIEW", "PRIORITY"}:
            new_status = "reopened"
            conn.execute(
                "INSERT INTO status_history(alert_id,old_status,new_status,changed_at,reason) VALUES(?,?,?,?,?)",
                (existing["id"], old_status, new_status, stamp, "New evidence raised the concern during post-action monitoring."),
            )
        deadline = existing["ack_deadline_at"] if "ack_deadline_at" in existing.keys() else None
        if should_route and (deadline is None or old_status in {"monitoring", "reopened"}):
            deadline = (now() + timedelta(minutes=(spot["ack_deadline_minutes"] if spot else 30))).isoformat()
        nearest_branch = nearest_authority_branch(conn, latest["latitude"], latest["longitude"]) if should_route else None
        assigned = nearest_branch[1]["police_id"] if nearest_branch else existing["assigned_to"]
        conn.execute(
            "UPDATE alerts SET tier=?,status=?,updated_at=?,ack_deadline_at=?,assigned_to=? WHERE id=?",
            (c["tier"], new_status, stamp, deadline, assigned, existing["id"]),
        )
        return existing["id"]

    aid = f"ALT-{uuid.uuid4().hex[:8].upper()}"
    deadline = None
    if should_route and spot:
        deadline = (now() + timedelta(minutes=spot["ack_deadline_minutes"] or 30)).isoformat()
    nearest_branch = nearest_authority_branch(conn, latest["latitude"], latest["longitude"]) if should_route else None
    assigned = nearest_branch[1]["police_id"] if nearest_branch else (spot["owner_police_id"] if should_route and spot else None)
    conn.execute(
        "INSERT INTO alerts(id,location_key,spot_id,location_label,latitude,longitude,tier,status,created_at,updated_at,assigned_to,ack_deadline_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (aid, loc_key, latest["spot_id"], latest["location_label"], latest["latitude"], latest["longitude"], c["tier"], "surfaced", stamp, stamp, assigned, deadline),
    )
    return aid


def require_authority(authorization: str | None):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Authority login required")
    raw = authorization.split(" ", 1)[1].strip()
    with closing(get_db()) as conn:
        row = conn.execute("SELECT s.token,s.police_id,s.expires_at,u.name,u.station,u.role FROM authority_sessions s JOIN authority_users u ON u.police_id=s.police_id WHERE s.token=?", (raw,)).fetchone()
        if not row:
            raise HTTPException(401, "Authority session is invalid")
        if datetime.fromisoformat(row["expires_at"]) < now():
            conn.execute("DELETE FROM authority_sessions WHERE token=?", (raw,))
            conn.commit()
            raise HTTPException(401, "Authority session expired")
        return dict(row)


def extract_evidence_text(filename: str, content: bytes) -> str:
    name = filename.lower()
    try:
        if name.endswith(".txt"):
            return content.decode("utf-8", errors="ignore")[:120000]
        if name.endswith(".pdf"):
            from pypdf import PdfReader
            import io
            reader = PdfReader(io.BytesIO(content))
            return "\n".join((p.extract_text() or "") for p in reader.pages)[:120000]
        if name.endswith(".docx"):
            from docx import Document
            import io
            doc = Document(io.BytesIO(content))
            return "\n".join(p.text for p in doc.paragraphs)[:120000]
    except Exception:
        return ""
    return ""


def action_terms(action_type: str | None):
    a = (action_type or "").lower()
    mapping = {
        "site inspection": ["inspect", "inspection", "site", "walkthrough", "observed", "checked", "finding"],
        "lighting inspection": ["light", "lighting", "lamp", "illumination", "lux", "fixture"],
        "increased patrol presence": ["patrol", "round", "beat", "presence", "officer", "deployment"],
        "cctv review": ["cctv", "camera", "footage", "recording", "video", "reviewed"],
        "local coordination": ["meeting", "coordination", "municipal", "security", "management", "committee"],
    }
    return mapping.get(a, ["action", "checked", "completed", "observed"])


def analyze_evidence_content(filename: str, content: bytes, action_type: str | None, location_label: str | None):
    text = extract_evidence_text(filename, content)
    if not text.strip():
        return {"status": "manual_review", "score": 0.25, "flags": ["no_extractable_text"], "summary": "The file was received and hashed, but no readable text was extracted. Human review is required."}
    import difflib
    lower = text.lower()
    terms = action_terms(action_type)
    hits = [t for t in terms if t in lower]
    # Small fuzzy check helps with ordinary wording variations without pretending to be an LLM.
    action_phrase = (action_type or "").lower().split()
    fuzzy_hits = [w for w in action_phrase if len(w) > 3 and any(difflib.SequenceMatcher(None, w, token).ratio() >= .78 for token in re.findall(r"[a-zA-Z]{4,}", lower))]
    flags = []
    checks = []
    if hits or fuzzy_hits:
        checks.append("action terms found")
    else:
        flags.append("action_content_mismatch")
    if len(text.strip()) < 120:
        flags.append("very_short_content")
    date_match = re.search(r"\b(?:20\d{2}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]20\d{2}|\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+20\d{2})\b", lower)
    if date_match: checks.append("date found")
    else: flags.append("no_obvious_date")
    if location_label:
        location_terms=[x.strip().lower() for x in re.split(r"[,·]", location_label) if len(x.strip())>=4]
        if any(x in lower for x in location_terms): checks.append("reported location found")
        else: flags.append("location_not_found_in_text")
    if re.search(r"\b(?:report|memo|inspection|patrol|review|action)\s*(?:no|number|id|ref|reference)?\s*[:#-]?\s*[a-z0-9/-]{3,}\b", lower):
        checks.append("document/reference identifier found")
    else:
        flags.append("no_obvious_document_reference")
    if re.search(r"\b(?:finding|findings|observed|observation|result|results|checked|inspection completed|action completed)\b", lower):
        checks.append("observation/result language found")
    else:
        flags.append("no_obvious_observation_or_result")
    score = 0.25 + 0.12 * min(3, len(hits) + len(fuzzy_hits)) + 0.1 * len(checks)
    if not flags: score += 0.15
    score = round(min(0.95, score), 2)
    status = "content_consistent" if not flags else "review_recommended"
    summary = f"Content assistant checked the uploaded record against the selected action. {len(checks)} consistency check(s) passed. " + ("No obvious content mismatch was found; this still does not prove authenticity." if not flags else "Human review is recommended because: " + ", ".join(flags) + ".")
    return {"status": status, "score": score, "flags": flags, "checks": checks, "summary": summary}


def evidence_precheck(filename: str, mime_type: str | None, size: int, content: bytes = b"", action_type: str | None = None, location_label: str | None = None) -> tuple[str, str, dict]:
    name = filename.lower()
    supported = (".pdf", ".doc", ".docx", ".txt", ".jpg", ".jpeg", ".png")
    if not name.endswith(supported):
        return "manual_review", "File type is not in the supported evidence set.", {"score": 0, "flags": ["unsupported_type"]}
    if size <= 0:
        return "manual_review", "Empty file cannot be used as completion evidence.", {"score": 0, "flags": ["empty_file"]}
    if size > 10 * 1024 * 1024:
        return "manual_review", "File exceeds the 10 MB demo evidence limit.", {"score": 0, "flags": ["too_large"]}
    if name.endswith((".jpg", ".jpeg", ".png")):
        return "manual_review", "Image evidence received and hashed. Visual authenticity is not established automatically; supervisor review is required.", {"score": 0.35, "flags": ["visual_evidence"]}
    analysis = analyze_evidence_content(filename, content, action_type, location_label)
    return analysis["status"], analysis["summary"], analysis


@app.on_event("startup")
def startup():
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "name": "SafeLine", "version": "4.3.0"}


@app.get("/api/spots")
def list_spots():
    with closing(get_db()) as conn:
        return [dict(r) for r in conn.execute("SELECT id,name,venue_type,zone_name,latitude,longitude FROM spots WHERE active=1 ORDER BY name")]


@app.post("/api/reports", response_model=ReportResponse, status_code=201)
def create_report(payload: ReportCreate, request: Request):
    enforce_rate_limit(f"report:{client_key(request)}", 20, 600)
    if payload.category not in CATEGORIES:
        raise HTTPException(400, "Unsupported report category")
    if payload.location_source == "gps" and not payload.location_consent:
        raise HTTPException(400, "Location consent is required for GPS reporting")
    if payload.location_source == "gps" and (payload.latitude is None or payload.longitude is None):
        raise HTTPException(400, "Current location could not be captured")
    if payload.location_source == "manual" and not payload.location_label:
        raise HTTPException(400, "Enter a public location or landmark")
    with closing(get_db()) as conn:
        spot = None
        # Server decides grounding. With GPS present, the nearest registered spot wins; a client cannot name a distant spot to upgrade evidence.
        if payload.latitude is not None and payload.longitude is not None:
            nearest = nearest_spot(conn, payload.latitude, payload.longitude)
            if nearest:
                spot = nearest[1]
        else:
            spot = get_spot(conn, payload.spot_id)
        if spot:
            spot_id = spot["id"]
            location_label = spot["name"]
            if payload.location_source == "gps" and payload.latitude is not None and payload.longitude is not None:
                # Ground the report to the registered spot for pattern grouping,
                # but preserve the actual one-time GPS point for authority context.
                lat, lon = payload.latitude, payload.longitude
                server_source = "gps"
                consent = 1
            else:
                lat, lon = spot["latitude"], spot["longitude"]
                server_source = "registered"
                consent = 1
        else:
            spot_id = None
            location_label = normalize_label(payload.location_label) if payload.location_label else "Current GPS location"
            lat, lon = payload.latitude, payload.longitude
            server_source = "gps" if lat is not None and lon is not None else "manual"
            consent = int(payload.location_consent)
        if server_source == "gps" and (lat is None or lon is None):
            raise HTTPException(400, "Choose a registered reporting spot when current GPS is unavailable")
        loc_key = location_key(spot_id, lat, lon, location_label)
        rid = f"RPT-{uuid.uuid4().hex[:8].upper()}"
        received = iso_now()
        stored_token = token_digest(payload.reporter_token)
        if len(payload.reporter_token) < 20:
            raise HTTPException(400, "Invalid pseudonymous reporter token")
        assigned_branch = nearest_authority_branch(conn, lat, lon)
        assigned_authority = assigned_branch[1]["police_id"] if assigned_branch else None
        if payload.offline_queue_id:
            existing_client = conn.execute("SELECT * FROM reports WHERE client_queue_id=?", (payload.offline_queue_id,)).fetchone()
            if existing_client:
                a = conn.execute("SELECT * FROM alerts WHERE id=?", (existing_client["alert_id"],)).fetchone() if existing_client["alert_id"] else None
                existing_branch = nearest_authority_branch(conn, existing_client["latitude"], existing_client["longitude"])
                return ReportResponse(report_id=existing_client["id"], spot_id=existing_client["spot_id"], spot_name=existing_client["location_label"], category=CATEGORIES[existing_client["category"]], received_at=existing_client["received_at"], status="received", latitude=existing_client["latitude"], longitude=existing_client["longitude"], location_label=existing_client["location_label"], location_source=existing_client["location_source"], assigned_to=existing_client["assigned_to"], assigned_authority=authority_name_from_location(existing_client["location_label"]) or (existing_branch[1]["name"] if existing_branch else None))
        cursor = conn.execute(
            """INSERT OR IGNORE INTO reports(id,spot_id,category,happened_when,reporter_type,still_happening,reporter_token,note,received_at,latitude,longitude,location_label,location_source,location_consent,location_key,event_weight,client_queue_id,assigned_to)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rid, spot_id, payload.category, payload.happened_when, payload.reporter_type, int(payload.still_happening), stored_token, payload.note.strip() if payload.note else None, received, lat, lon, location_label, server_source, consent, loc_key, {"just_now":1.0,"earlier_today":0.7,"earlier":0.4}[payload.happened_when], payload.offline_queue_id, assigned_authority),
        )
        if cursor.rowcount == 0 and payload.offline_queue_id:
            existing_client = conn.execute("SELECT * FROM reports WHERE client_queue_id=?", (payload.offline_queue_id,)).fetchone()
            if existing_client:
                conn.rollback()
                existing_branch = nearest_authority_branch(conn, existing_client["latitude"], existing_client["longitude"])
                return ReportResponse(report_id=existing_client["id"], spot_id=existing_client["spot_id"], spot_name=existing_client["location_label"], category=CATEGORIES[existing_client["category"]], received_at=existing_client["received_at"], status="received", latitude=existing_client["latitude"], longitude=existing_client["longitude"], location_label=existing_client["location_label"], location_source=existing_client["location_source"], assigned_to=existing_client["assigned_to"], assigned_authority=authority_name_from_location(existing_client["location_label"]) or (existing_branch[1]["name"] if existing_branch else None))
        assign_occurrence(conn, rid, loc_key, spot_id, payload.category, received)
        alert_id = refresh_alert(conn, loc_key)
        if alert_id:
            conn.execute("UPDATE reports SET alert_id=? WHERE id=?", (alert_id, rid))
        conn.commit()
        invalidate_summary_cache()
        return ReportResponse(report_id=rid, spot_id=spot_id, spot_name=location_label, category=CATEGORIES[payload.category], received_at=received, status="received", latitude=lat, longitude=lon, location_label=location_label, location_source=server_source, assigned_to=assigned_authority, assigned_authority=authority_name_from_location(location_label) or (assigned_branch[1]["name"] if assigned_branch else None))


@app.post("/api/reports/offline-relay", response_model=ReportResponse, status_code=201)
def relay_offline_report(payload: ReportCreate, request: Request):
    """Accept a report captured while the citizen was offline and process it
    through the same server-side validation/grounding pipeline as a live report.
    The client-generated OFF-* queue id is never used as the authoritative report id.
    """
    return create_report(payload, request)

@app.post("/api/help-now")
def help_now(payload: dict, request: Request):
    enforce_rate_limit(f"help:{client_key(request)}", 5, 600)
    lat, lon = payload.get("latitude"), payload.get("longitude")
    if lat is None or lon is None:
        raise HTTPException(400, "Current location is required before requesting location-based assistance")
    with closing(get_db()) as conn:
        hid = f"HELP-{uuid.uuid4().hex[:8].upper()}"
        conn.execute("INSERT INTO assistance_requests(id,latitude,longitude,location_label,created_at) VALUES(?,?,?,?,?)", (hid, lat, lon, payload.get("location_label") or "Current location", iso_now()))
        conn.commit()
        return {"request_id": hid, "status": "requested", "latitude": lat, "longitude": lon, "location_label": payload.get("location_label") or "Current location", "map_url": payload.get("map_url") or f"https://www.google.com/maps/search/?api=1&query={lat},{lon}", "message": "Location-based assistance request recorded. For immediate danger, call 112 directly."}


@app.post("/api/reports/{report_id}/context")
def update_report_context(report_id: str, payload: ReportContextUpdate, request: Request):
    enforce_rate_limit(f"context:{client_key(request)}", 20, 600)
    digest = token_digest(payload.reporter_token)
    with closing(get_db()) as conn:
        r = conn.execute("SELECT * FROM reports WHERE id=? AND reporter_token=?", (report_id, digest)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found for this browser")
        if r["authority_status"] != "new":
            raise HTTPException(409, "Authority review has already started; context can no longer be edited")
        weight = {"just_now":1.0,"earlier_today":0.7,"earlier":0.4}[payload.happened_when]
        conn.execute("UPDATE reports SET happened_when=?,reporter_type=?,still_happening=?,note=?,event_weight=? WHERE id=?", (payload.happened_when,payload.reporter_type,int(payload.still_happening),payload.note.strip() if payload.note else None,weight,report_id))
        conn.commit()
    return {"status":"updated","report_id":report_id}

@app.post("/api/reports/{report_id}/undo")
def undo_report(report_id: str, payload: dict, request: Request):
    enforce_rate_limit(f"undo:{client_key(request)}", 10, 60)
    raw_token = str(payload.get("reporter_token") or "")
    if len(raw_token) < 20:
        raise HTTPException(400, "Invalid local report token")
    digest = token_digest(raw_token)
    with closing(get_db()) as conn:
        r = conn.execute("SELECT * FROM reports WHERE id=? AND reporter_token=?", (report_id, digest)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found for this browser")
        age = (now() - datetime.fromisoformat(r["received_at"])).total_seconds()
        if age > 5 or r["authority_status"] != "new":
            raise HTTPException(409, "The undo window has closed")
        loc_key = r["location_key"]
        conn.execute("DELETE FROM occurrence_reports WHERE report_id=?", (report_id,))
        conn.execute("DELETE FROM occurrences WHERE id NOT IN (SELECT occurrence_id FROM occurrence_reports)")
        conn.execute("DELETE FROM reports WHERE id=?", (report_id,))
        if conn.execute("SELECT 1 FROM reports WHERE location_key=? LIMIT 1", (loc_key,)).fetchone() is None:
            conn.execute("DELETE FROM alerts WHERE location_key=?", (loc_key,))
        invalidate_summary_cache()
        conn.commit()
    return {"status":"undone","report_id":report_id}

@app.get("/api/reports/{report_id}")
def get_report(report_id: str):
    with closing(get_db()) as conn:
        r = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found")
        a = conn.execute("SELECT id,status,tier,action_type,updated_at FROM alerts WHERE id=?", (r["alert_id"],)).fetchone() if r["alert_id"] else latest_alert_for_location(conn, r["location_key"])
        raw_status = effective_case_status(conn, a) if a else "surfaced"
        if raw_status in {"completed"}: workflow = "completed"
        elif raw_status == "monitoring": workflow = "monitoring"
        elif raw_status == "reopened": workflow = "reopened"
        elif raw_status in {"action_planned", "action_due"}: workflow = "action_in_progress"
        elif raw_status == "reviewing": workflow = "under_review"
        elif r["authority_status"] == "acknowledged": workflow = "acknowledged"
        else: workflow = "received"
        branch = nearest_authority_branch(conn, r["latitude"], r["longitude"])
        return {"report_id": r["id"], "spot_name": r["location_label"], "category": CATEGORIES.get(r["category"], r["category"]), "received_at": r["received_at"], "status": workflow, "tier": a["tier"] if a else "WATCH", "location_label": r["location_label"], "action_type": a["action_type"] if a else None, "authority_status": r["authority_status"], "assigned_to": r["assigned_to"], "assigned_authority": authority_name_from_location(r["location_label"]) or (branch[1]["name"] if branch else None)}


@app.post("/api/authority/login")
def authority_login(payload: AuthorityLogin):
    with closing(get_db()) as conn:
        user = conn.execute("SELECT * FROM authority_users WHERE police_id=?", (payload.police_id.strip().upper(),)).fetchone()
        if not user or not verify_pin(payload.pin, user["pin"]):
            raise HTTPException(401, "Invalid demo police ID or PIN")
        token_value = uuid.uuid4().hex + uuid.uuid4().hex
        created = now()
        expires = created + timedelta(hours=8)
        conn.execute("INSERT INTO authority_sessions(token,police_id,created_at,expires_at) VALUES(?,?,?,?)", (token_value, user["police_id"], created.isoformat(), expires.isoformat()))
        conn.commit()
        return {"token": token_value, "police_id": user["police_id"], "name": user["name"], "station": user["station"], "role": user["role"], "expires_at": expires.isoformat()}


@app.get("/api/authority/me")
def authority_me(authorization: str | None = Header(default=None)):
    return require_authority(authorization)


@app.post("/api/authority/logout")
def authority_logout(authorization: str | None = Header(default=None)):
    session = require_authority(authorization)
    with closing(get_db()) as conn:
        conn.execute("DELETE FROM authority_sessions WHERE token=?", (authorization.split(" ", 1)[1].strip(),))
        conn.commit()
    return {"status": "logged_out", "police_id": session["police_id"]}


@app.get("/api/reports/mine/{reporter_token}")
def my_reports(reporter_token: str):
    if len(reporter_token) < 20:
        raise HTTPException(400, "Invalid local report token")
    digest = token_digest(reporter_token)
    with closing(get_db()) as conn:
        rows = conn.execute("""
            SELECT r.id,r.category,r.received_at,r.location_label,r.authority_status,
                   a.id alert_id,a.status,a.tier,a.action_type,a.updated_at
            FROM reports r LEFT JOIN alerts a ON a.id=r.alert_id
            WHERE r.reporter_token=? ORDER BY r.received_at DESC LIMIT 25
        """, (digest,)).fetchall()
        out=[]
        for r in rows:
            raw=r["status"] or "surfaced"
            if raw=="completed": workflow="completed"
            elif raw=="monitoring": workflow="monitoring"
            elif raw=="reopened": workflow="reopened"
            elif raw in {"action_planned","action_due"}: workflow="action_in_progress"
            elif raw=="reviewing": workflow="under_review"
            elif r["authority_status"]=="acknowledged": workflow="acknowledged"
            else: workflow="received"
            out.append({**dict(r), "category_label": CATEGORIES.get(r["category"], r["category"]), "status": workflow, "tier": r["tier"] or "WATCH"})
        return out


@app.post("/api/planning/overview")
def planning_overview(payload: PlanningQuery, request: Request):
    enforce_rate_limit(f"plan:{client_key(request)}", 30, 60)
    with closing(get_db()) as conn:
        nearby = []
        for r in conn.execute("SELECT * FROM reports WHERE latitude IS NOT NULL AND longitude IS NOT NULL ORDER BY received_at DESC LIMIT 1000").fetchall():
            d = distance_m(payload.latitude, payload.longitude, r["latitude"], r["longitude"])
            if d is not None and d <= payload.radius_km * 1000:
                nearby.append((r, d))
        recent_cut = now() - timedelta(days=30)
        recent = [x for x in nearby if datetime.fromisoformat(x[0]["received_at"]) >= recent_cut]
        sources = len({x[0]["reporter_token"] for x in recent})
        categories = {}
        for r, _ in recent:
            categories[CATEGORIES.get(r["category"], r["category"])] = categories.get(CATEGORIES.get(r["category"], r["category"]), 0) + 1
        active_alerts = []
        for a in conn.execute("SELECT * FROM alerts WHERE status NOT IN ('completed')").fetchall():
            if a["latitude"] is not None and a["longitude"] is not None:
                d = distance_m(payload.latitude, payload.longitude, a["latitude"], a["longitude"])
                if d is not None and d <= payload.radius_km * 1000:
                    active_alerts.append({"signal": "active pattern concern", "status": "under authority review" if a["status"] not in {"completed"} else "monitoring", "location_label": a["location_label"], "distance_m": round(d)})
        is_demo_data = False
        if not recent:
            # Keep planning useful during a hackathon demo even for a location that has no
            # seeded reports. These values are explicitly labelled synthetic; they never
            # enter the authority scoring engine or create alerts.
            is_demo_data = True
            categories = {"Catcalling": 4, "Following": 3, "Loitering / Blocking": 2, "Unwanted approach": 2, "Threatening behaviour": 1}
            demo_reports = sum(categories.values())
            demo_sources = 8
            signal = "Demo activity snapshot"
            explanation = "No real SafeLine reports were found within the selected radius. The planner is showing synthetic demo activity so the feature remains demonstrable for new locations; this data is not used for authority decisions."
            return {"radius_km": payload.radius_km, "reports_30d": demo_reports, "distinct_sources_30d": demo_sources, "signal": signal, "explanation": explanation, "categories": categories, "active_concerns": [], "is_demo_data": True}
        if active_alerts:
            signal = "Repeated activity needs attention"
            explanation = "Recent reports include one or more active pattern concerns in this area. Review the details before relying on the snapshot."
        elif len(recent) <= 2:
            signal = "Low reported activity"
            explanation = "A small number of reports were recorded recently. Low reporting is not proof that no incidents occur."
        else:
            signal = "Some reported activity"
            explanation = "Reports exist in the selected area, but the current data does not meet the system's active concern gates."
        return {"radius_km": payload.radius_km, "reports_30d": len(recent), "distinct_sources_30d": sources, "signal": signal, "explanation": explanation, "categories": categories, "active_concerns": active_alerts[:10], "is_demo_data": False}


def apply_routing_escalations(conn):
    current=now()
    rows=conn.execute("SELECT a.*,s.backup_police_id FROM alerts a LEFT JOIN spots s ON s.id=a.spot_id WHERE a.ack_deadline_at IS NOT NULL AND a.ack_deadline_at<? AND a.status IN ('surfaced','acknowledged')",(current.isoformat(),)).fetchall()
    for a in rows:
        backup=a["backup_police_id"]
        if backup and a["escalated_at"] is None:
            conn.execute("UPDATE alerts SET assigned_to=?,escalated_at=?,updated_at=? WHERE id=?",(backup,current.isoformat(),current.isoformat(),a["id"]))
            conn.execute("INSERT INTO status_history(alert_id,old_status,new_status,changed_at,reason) VALUES(?,?,?,?,?)",(a["id"],a["status"],a["status"],current.isoformat(),f"Routing escalation: acknowledgement deadline exceeded; backup authority {backup} assigned."))


@app.get("/api/authority/summary")
def authority_summary(authorization: str | None = Header(default=None)):
    require_authority(authorization)
    import time
    if _SUMMARY_CACHE["data"] is not None and time.time() - _SUMMARY_CACHE["at"] < 3.0:
        return _SUMMARY_CACHE["data"]
    with closing(get_db()) as conn:
        apply_routing_escalations(conn)
        conn.commit()
        locations = conn.execute("SELECT location_key, MAX(received_at) last_report_at FROM reports GROUP BY location_key ORDER BY last_report_at DESC").fetchall()
        concerns = []
        for loc in locations:
            loc_key = loc["location_key"]
            c = concern_for(conn, loc_key)
            a = latest_alert_for_location(conn, loc_key)
            first = conn.execute("SELECT * FROM reports WHERE location_key=? ORDER BY received_at LIMIT 1", (loc_key,)).fetchone()
            if not a:
                continue
            concerns.append({
                "alert_id": a["id"], "location_key": loc_key, "spot_id": a["spot_id"],
                "spot_name": a["location_label"], "zone_name": (get_spot(conn, a["spot_id"])["zone_name"] if a["spot_id"] and get_spot(conn, a["spot_id"]) else "Unregistered location"),
                "tier": c["tier"], "status": effective_case_status(conn, a), "latitude": a["latitude"], "longitude": a["longitude"],
                **c, "last_report_at": loc["last_report_at"], "location_source": first["location_source"],
            })
        order = {"PRIORITY": 0, "REVIEW": 1, "REPORTING-PATTERN REVIEW": 2, "WATCH": 3}
        concerns.sort(key=lambda x: x.get("last_report_at") or "", reverse=True)
        recent_rows = conn.execute("""
            SELECT r.id,r.category,r.reporter_type,r.received_at,r.location_label,r.location_source,r.latitude,r.longitude,r.authority_status,r.acknowledged_at,r.acknowledged_by,r.assigned_to,
                   a.id AS alert_id,a.tier,a.status AS concern_status
            FROM reports r LEFT JOIN alerts a ON a.id=r.alert_id
            ORDER BY r.received_at DESC LIMIT 80
        """).fetchall()
        recent_reports = []
        for r in recent_rows:
            row = dict(r)
            row["category_label"] = CATEGORIES.get(r["category"], r["category"])
            branch = nearest_authority_branch(conn, r["latitude"], r["longitude"])
            row["assigned_authority"] = branch[1]["name"] if branch else None
            row["tier"] = r["tier"] or "WATCH"
            if r["alert_id"]:
                ar = conn.execute("SELECT * FROM alerts WHERE id=?", (r["alert_id"],)).fetchone()
                row["status"] = effective_case_status(conn, ar) if ar else (r["concern_status"] or "received")
            else:
                row["status"] = "received"
            recent_reports.append(row)
        result = {
            "concerns": concerns,
            "recent_reports": recent_reports,
            "counts": {
                "priority": sum(x["tier"] == "PRIORITY" for x in concerns),
                "review": sum(x["tier"] == "REVIEW" for x in concerns),
                "integrity": sum(x["tier"] == "REPORTING-PATTERN REVIEW" for x in concerns),
                "watch": sum(x["tier"] == "WATCH" for x in concerns),
                "actions_due": conn.execute("SELECT COUNT(*) n FROM alerts WHERE status IN ('action_planned','action_due')").fetchone()["n"],
                "reports": conn.execute("SELECT COUNT(*) n FROM reports").fetchone()["n"],
                "new_reports": conn.execute("SELECT COUNT(*) n FROM reports WHERE authority_status='new'").fetchone()["n"],
                "overdue": conn.execute("SELECT COUNT(*) n FROM alerts WHERE ack_deadline_at IS NOT NULL AND ack_deadline_at<? AND status IN ('surfaced','acknowledged')", (iso_now(),)).fetchone()["n"],
            },
            "context_events": [dict(r) for r in conn.execute("SELECT * FROM context_events ORDER BY start_at DESC LIMIT 20")],
        }
        import time
        _SUMMARY_CACHE["data"] = result
        _SUMMARY_CACHE["at"] = time.time()
        return result



def evidence_analysis_for_row(row, location_label=None):
    try:
        path = row.get("stored_path") if isinstance(row, dict) else row["stored_path"]
        if not path or not Path(path).exists():
            return {"status":"manual_review","checks":[],"flags":["stored_file_unavailable"],"summary":"The evidence record is present, but the stored file is unavailable for content assistance."}
        content = Path(path).read_bytes()
        action = row.get("action_type") if isinstance(row, dict) else row["action_type"]
        analysis = analyze_evidence_content(row["filename"], content, action, location_label)
        lower = (extract_evidence_text(row["filename"], content) or "").lower()
        components = {
            "case_reference": "record present; direct case-ID match requires human review",
            "location": "match" if location_label and any(x.strip().lower() in lower for x in re.split(r"[,·]", location_label) if len(x.strip())>=4) else "not found / review",
            "subject_action": "match" if "action terms found" in analysis.get("checks",[]) else "attention required",
            "date_time": "consistent" if "date found" in analysis.get("checks",[]) else "not found / review",
            "responsible_unit": "not independently verified",
            "document_type": (Path(row["filename"]).suffix.lower().lstrip(".") or "unknown") + " · relevant file type",
            "required_observation": "present" if "observation/result language found" in analysis.get("checks",[]) else "not found / review",
            "provenance": "SHA-256 recorded; upload metadata retained",
        }
        analysis["components"] = components
        analysis["relevance_label"] = "Relevant to recorded action" if not analysis.get("flags") else "Attention required"
        return analysis
    except Exception as exc:
        return {"status":"manual_review","checks":[],"flags":["analysis_unavailable"],"summary":"Content assistance could not be completed; human review is required."}

@app.get("/api/authority/concerns/{alert_id}")
def concern_detail(alert_id: str, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not a:
            raise HTTPException(404, "Concern not found")
        c = concern_for(conn, a["location_key"])
        reports = conn.execute(
            "SELECT id,category,happened_when,reporter_type,still_happening,received_at,latitude,longitude,location_label,location_source FROM reports WHERE location_key=? ORDER BY received_at DESC LIMIT 80",
            (a["location_key"],),
        ).fetchall()
        zone = get_spot(conn, a["spot_id"]) if a["spot_id"] else None
        verification = (
            dict(conn.execute(
                "SELECT outcome,note,reviewed_by,reviewed_at FROM concern_verifications WHERE alert_id=? ORDER BY reviewed_at DESC LIMIT 1",
                (alert_id,),
            ).fetchone())
            if conn.execute("SELECT 1 FROM concern_verifications WHERE alert_id=? LIMIT 1", (alert_id,)).fetchone()
            else None
        )
        # This is the explicit bridge between the production intelligence engine and
        # the authority UI. The values below are derived by concern_for(); they are not
        # frontend-generated labels or an LLM judgement.
        processing = {
            "report_count": c["report_count"],
            "distinct_reporters": c["distinct_reporters"],
            "effective_signal": c["effective_signal"],
            "occurrence_count": c["occurrence_count"],
            "active_days": c["active_days"],
            "recent_rate": c["recent_rate"],
            "baseline": c["baseline"],
            "trend": c["trend"],
            "integrity_flags": c["integrity_flags"],
            "context": c["context"],
            "tier": c["tier"],
            "why": c["why"],
            "held_back": c["held_back"],
        }
        case_status = effective_case_status(conn, a)
        return {
            **dict(a),
            "status": case_status,
            **c,
            "zone_name": zone["zone_name"] if zone else "Unregistered location",
            "incident_latitude": a["latitude"],
            "incident_longitude": a["longitude"],
            "location_source": (reports[0]["location_source"] if reports else "stored"),
            "processing": processing,
            "decision": {
                "tier": c["tier"],
                "routed_to_authority": c["tier"] in {"REVIEW", "PRIORITY", "REPORTING-PATTERN REVIEW"},
                "human_review_required": True,
                "why": c["why"],
                "held_back": c["held_back"],
            },
            "reports": [{**dict(r), "category_label": CATEGORIES.get(r["category"], r["category"])} for r in reports],
            "status_history": [dict(r) for r in conn.execute("SELECT old_status,new_status,changed_at,reason FROM status_history WHERE alert_id=? ORDER BY changed_at DESC", (alert_id,)).fetchall()],
            "evidence": [{**dict(r), "ai_analysis": evidence_analysis_for_row(dict(r), a["location_label"])} for r in conn.execute("SELECT id,alert_id,filename,stored_path,mime_type,size_bytes,sha256,uploaded_at,uploaded_by,precheck_status,precheck_summary,action_type,supervisor_approved,approved_at,approved_by,approval_note FROM action_evidence WHERE alert_id=? ORDER BY uploaded_at DESC", (alert_id,)).fetchall()],
            "verification": verification,
        }


@app.post("/api/authority/concerns/{alert_id}/status")
def update_status(alert_id: str, payload: StatusUpdate, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        a = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
        if not a:
            raise HTTPException(404, "Concern not found")
        if payload.status in {"completed", "monitoring"} and not (payload.observation and payload.observation.strip()):
            raise HTTPException(400, "A structured observation is required before completion or monitoring")
        if payload.status == "completed":
            if a["status"] == "completed":
                raise HTTPException(409, "This case is already completed. Start monitoring from the supervisor-approved case.")
            verification = conn.execute("SELECT 1 FROM concern_verifications WHERE alert_id=? LIMIT 1", (alert_id,)).fetchone()
            if not verification:
                raise HTTPException(400, "Human verification must be recorded before completion")
            evidence = conn.execute("SELECT * FROM action_evidence WHERE alert_id=? AND supervisor_approved=1 AND (action_type=? OR action_type IS NULL) ORDER BY approved_at DESC LIMIT 1", (alert_id, a["action_type"])).fetchone()
            if not evidence:
                raise HTTPException(400, "Upload and supervisor-approve a completion report before marking the action completed")
            if evidence["approved_by"] == evidence["uploaded_by"]:
                raise HTTPException(400, "Completion evidence must be approved by a different authority user than the uploader")
        if payload.status == "monitoring":
            if a["status"] != "completed":
                raise HTTPException(400, "Monitoring can start only after the case is completed and supervisor-approved")
            evidence = conn.execute("SELECT 1 FROM action_evidence WHERE alert_id=? AND supervisor_approved=1", (alert_id,)).fetchone()
            if not evidence:
                raise HTTPException(400, "Supervisor-approved evidence is required before monitoring starts")
        stamp = iso_now()
        conn.execute(
            "UPDATE alerts SET status=?,updated_at=?,action_type=?,observation=? WHERE id=?",
            (payload.status, stamp, payload.action_type or a["action_type"], payload.observation or a["observation"], alert_id),
        )
        reason = f"{officer['police_id']}: {payload.observation or payload.action_type or payload.status}"
        conn.execute("INSERT INTO status_history(alert_id,old_status,new_status,changed_at,reason) VALUES(?,?,?,?,?)", (alert_id, a["status"], payload.status, stamp, reason))
        conn.commit()
        invalidate_summary_cache()
        return {"status": payload.status}


@app.post("/api/authority/reports/{report_id}/acknowledge")
def acknowledge_report(report_id: str, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        r = conn.execute("SELECT id,authority_status,alert_id,location_key FROM reports WHERE id=?", (report_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Report not found")
        stamp = iso_now()
        conn.execute("UPDATE reports SET authority_status='acknowledged', acknowledged_at=?, acknowledged_by=? WHERE id=?", (stamp, officer["police_id"], report_id))
        if r["alert_id"]:
            a = conn.execute("SELECT * FROM alerts WHERE id=?", (r["alert_id"],)).fetchone()
            if a and a["status"] == "surfaced":
                conn.execute("UPDATE alerts SET status='acknowledged',assigned_to=?,updated_at=? WHERE id=?", (officer["police_id"], stamp, a["id"]))
                conn.execute("INSERT INTO status_history(alert_id,old_status,new_status,changed_at,reason) VALUES(?,?,?,?,?)", (a["id"], "surfaced", "acknowledged", stamp, f"{officer['police_id']} acknowledged report {report_id}"))
        conn.commit()
        invalidate_summary_cache()
        return {"report_id": report_id, "authority_status": "acknowledged", "acknowledged_at": stamp}


@app.post("/api/authority/assistance/{request_id}/acknowledge")
def acknowledge_assistance(request_id: str, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        r = conn.execute("SELECT id FROM assistance_requests WHERE id=?", (request_id,)).fetchone()
        if not r:
            raise HTTPException(404, "Assistance request not found")
        stamp = iso_now()
        conn.execute("UPDATE assistance_requests SET status='acknowledged', acknowledged_by=?, acknowledged_at=? WHERE id=?", (officer["police_id"], stamp, request_id))
        conn.commit()
        return {"request_id": request_id, "status": "acknowledged", "acknowledged_at": stamp}


@app.post("/api/authority/reports/{report_id}/integrity")
def review_report_integrity(report_id: str, payload: IntegrityReview, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        if not conn.execute("SELECT id FROM reports WHERE id=?", (report_id,)).fetchone():
            raise HTTPException(404, "Report not found")
        conn.execute("INSERT INTO report_reviews(report_id,classification,note,reviewed_by,reviewed_at) VALUES(?,?,?,?,?)", (report_id,payload.classification,payload.note,officer["police_id"],iso_now()))
        # Integrity review is part of downstream scoring, so force the authority
        # summary to be recalculated immediately rather than waiting for cache expiry.
        report = conn.execute("SELECT location_key FROM reports WHERE id=?", (report_id,)).fetchone()
        if report and report["location_key"]:
            refresh_alert(conn, report["location_key"])
        conn.commit()
        invalidate_summary_cache()
        return {"report_id": report_id, "classification": payload.classification, "reviewed_by": officer["police_id"]}


def analyze_report_content(conn, report_id: str):
    r = conn.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
    if not r: raise HTTPException(404, "Report not found")
    note = (r["note"] or "").strip()
    flags=[]
    pii=[]
    if note:
        if re.search(r"\b\+?\d[\d\s-]{7,}\b", note): pii.append("possible_phone_number")
        if re.search(r"@[A-Za-z0-9._-]+", note): pii.append("possible_email")
        if re.search(r"\b(?:my name is|his name is|her name is|called)\s+[A-Z][a-z]+", note, re.I): pii.append("possible_person_name")
        category_terms={
            "catcalling":["comment","shout","catcall","remark"], "following":["follow","behind","trail"],
            "loitering_blocking":["block","loiter","stand","gate"], "threatening":["threat","threaten","intimidat"],
            "unwanted_approach":["approach","came up","follow"], "other":[]
        }
        terms=category_terms.get(r["category"],[])
        if terms and not any(t in note.lower() for t in terms): flags.append("note_category_mismatch_possible")
    if pii: flags.extend(pii)
    if len(note)<8: flags.append("minimal_context")
    score=max(0.0,min(1.0,0.75-0.12*len(flags)))
    summary=("No obvious content anomaly was found in the optional note." if not flags else "Flags for human attention: "+", ".join(flags)+".")
    conn.execute("INSERT INTO report_ai_reviews(report_id,review_type,score,flags,summary,created_at) VALUES(?,?,?,?,?,?)",(report_id,"citizen_note",score,json_compact(flags),summary,iso_now()))
    conn.commit()
    return {"score":score,"flags":flags,"summary":summary,"engine":"rule-based content assistant (not a truth detector)"}


@app.get("/api/authority/reports/{report_id}/analysis")
def report_analysis(report_id: str, authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        latest=conn.execute("SELECT * FROM report_ai_reviews WHERE report_id=? ORDER BY created_at DESC LIMIT 1",(report_id,)).fetchone()
        if latest: return {"score":latest["score"],"flags":__import__("json").loads(latest["flags"] or "[]"),"summary":latest["summary"],"engine":"rule-based content assistant (not a truth detector)"}
        return analyze_report_content(conn,report_id)


@app.post("/api/authority/reports/{report_id}/verification")
def persist_verification(report_id: str, payload: VerificationOutcome, authorization: str | None = Header(default=None)):
    officer=require_authority(authorization)
    with closing(get_db()) as conn:
        if not conn.execute("SELECT id FROM reports WHERE id=?",(report_id,)).fetchone(): raise HTTPException(404,"Report not found")
        conn.execute("INSERT INTO report_reviews(report_id,classification,note,reviewed_by,reviewed_at,verification_outcome) VALUES(?,?,?,?,?,?)",(report_id,"authority_verification",payload.note,officer["police_id"],iso_now(),payload.outcome))
        conn.commit()
        return {"report_id":report_id,"outcome":payload.outcome,"reviewed_by":officer["police_id"]}


@app.post("/api/authority/concerns/{alert_id}/verification")
async def persist_concern_verification(alert_id: str, request: Request, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    outcome = payload.get("outcome") if isinstance(payload, dict) else None
    note = payload.get("note") if isinstance(payload, dict) else None
    allowed = {"pattern_confirmed", "pattern_not_confirmed", "insufficient_evidence", "context_explains", "reporting_integrity_concern"}
    if outcome not in allowed:
        raise HTTPException(422, "Select a valid verification outcome.")
    if note is not None and not isinstance(note, str):
        raise HTTPException(422, "Verification observation must be text.")
    if note and len(note) > 700:
        raise HTTPException(422, "Verification observation is too long.")
    with closing(get_db()) as conn:
        if not conn.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone():
            raise HTTPException(404, "Concern not found")
        conn.execute("INSERT INTO concern_verifications(alert_id,outcome,note,reviewed_by,reviewed_at) VALUES(?,?,?,?,?)", (alert_id, outcome, note, officer["police_id"], iso_now()))
        conn.commit()
        invalidate_summary_cache()
        return {"alert_id": alert_id, "outcome": outcome, "reviewed_by": officer["police_id"]}


@app.post("/api/authority/concerns/{alert_id}/evidence")
def upload_evidence(alert_id: str, file: UploadFile = File(...), action_type: str | None = Form(default=None), authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    with closing(get_db()) as conn:
        if not conn.execute("SELECT id FROM alerts WHERE id=?", (alert_id,)).fetchone():
            raise HTTPException(404, "Concern not found")
        content = file.file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(400, "Evidence file must be 10 MB or smaller")
        import hashlib
        evidence_id = f"EVD-{uuid.uuid4().hex[:8].upper()}"
        folder = BASE_DIR / "evidence"
        folder.mkdir(exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", file.filename or "completion_report")[:120]
        stored = folder / f"{evidence_id}_{safe_name}"
        stored.write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        alert_row = conn.execute("SELECT action_type,location_label FROM alerts WHERE id=?", (alert_id,)).fetchone()
        precheck, summary, analysis = evidence_precheck(file.filename or safe_name, file.content_type, len(content), content, action_type or (alert_row["action_type"] if alert_row else None), alert_row["location_label"] if alert_row else None)
        stamp = iso_now()
        conn.execute("INSERT INTO action_evidence(id,alert_id,filename,stored_path,mime_type,size_bytes,sha256,uploaded_at,uploaded_by,precheck_status,precheck_summary,action_type) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (evidence_id,alert_id,file.filename or safe_name,str(stored),file.content_type,len(content),digest,stamp,officer["police_id"],precheck,summary,action_type or (alert_row["action_type"] if alert_row else None)))
        conn.commit()
        invalidate_summary_cache()
        return {"evidence_id": evidence_id, "filename": file.filename, "precheck_status": precheck, "precheck_summary": summary, "ai_analysis": analysis, "sha256": digest, "uploaded_by": officer["police_id"]}


@app.get("/api/authority/evidence/{evidence_id}/file")
def open_evidence_file(evidence_id: str, authorization: str | None = Header(default=None)):
    """Serve one case-scoped evidence file to an authenticated authority user.

    The file is read from the evidence record rather than from a client-supplied path,
    so the supervisor can inspect the exact document attached to the current case.
    """
    require_authority(authorization)
    with closing(get_db()) as conn:
        evidence = conn.execute(
            "SELECT id,filename,stored_path,mime_type FROM action_evidence WHERE id=?",
            (evidence_id,),
        ).fetchone()
        if not evidence:
            raise HTTPException(404, "Evidence not found")

    stored_path = Path(evidence["stored_path"]).resolve()
    evidence_dir = (BASE_DIR / "evidence").resolve()
    try:
        stored_path.relative_to(evidence_dir)
    except ValueError:
        raise HTTPException(403, "Evidence file is outside the evidence store")

    if not stored_path.is_file():
        raise HTTPException(404, "Evidence file is no longer available")

    # Browsers need a reliable PDF MIME type to open the native PDF viewer.
    # Some uploads arrive with application/octet-stream even when the filename is .pdf.
    import mimetypes
    filename = evidence["filename"] or stored_path.name
    media_type = (evidence["mime_type"] or "").split(";", 1)[0].strip()
    if not media_type or media_type == "application/octet-stream":
        media_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"

    return FileResponse(
        path=str(stored_path),
        media_type=media_type,
        filename=filename,
        content_disposition_type="inline",
        headers={"X-SafeLine-Evidence-Id": evidence_id},
    )


@app.post("/api/authority/evidence/{evidence_id}/approve")
async def approve_evidence(evidence_id: str, request: Request, authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    try:
        payload = await request.json()
    except Exception:
        payload = {}
    approved = True if not isinstance(payload, dict) else bool(payload.get("approved", True))
    note = None if not isinstance(payload, dict) else payload.get("note")
    with closing(get_db()) as conn:
        e = conn.execute("SELECT * FROM action_evidence WHERE id=?", (evidence_id,)).fetchone()
        if not e:
            raise HTTPException(404, "Evidence not found")
        if approved:
            if officer["role"] != "Station Supervisor":
                raise HTTPException(403, "Station Supervisor approval required")
            if e["uploaded_by"] == officer["police_id"]:
                raise HTTPException(403, "A supervisor cannot approve their own uploaded evidence")
        stamp = iso_now()
        conn.execute("UPDATE action_evidence SET supervisor_approved=?,approved_at=?,approved_by=?,approval_note=? WHERE id=?", (int(approved), stamp if approved else None, officer["police_id"] if approved else None, note, evidence_id))
        conn.commit()
        invalidate_summary_cache()
        return {"evidence_id": evidence_id, "supervisor_approved": approved, "approved_by": officer["police_id"] if approved else None, "message": "Supervisor approval recorded." if approved else "Supervisor approval removed."}


@app.get("/api/authority/concerns/{alert_id}/evidence")
def list_evidence(alert_id: str, authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT id,alert_id,filename,mime_type,size_bytes,sha256,uploaded_at,uploaded_by,precheck_status,precheck_summary,action_type,supervisor_approved,approved_at,approved_by,approval_note FROM action_evidence WHERE alert_id=? ORDER BY uploaded_at DESC", (alert_id,)).fetchall()
        return [dict(r) for r in rows]


@app.get("/api/authority/map")
def authority_map(authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        rows = conn.execute(
            "SELECT r.id,r.category,r.received_at,r.latitude,r.longitude,r.location_label,r.location_source,r.location_key,r.spot_id,r.assigned_to FROM reports r WHERE r.latitude IS NOT NULL AND r.longitude IS NOT NULL ORDER BY r.received_at DESC LIMIT 300"
        ).fetchall()
        spots = conn.execute("SELECT id,name,latitude,longitude,zone_name FROM spots WHERE active=1").fetchall()
        branches = conn.execute("SELECT id,name,police_id,role,latitude,longitude,zone_name FROM authority_branches WHERE active=1 ORDER BY name").fetchall()
        assistance = conn.execute("SELECT * FROM assistance_requests WHERE status='requested' ORDER BY created_at DESC LIMIT 30").fetchall()
        report_items = []
        for r in rows:
            item = {**dict(r), "category_label": CATEGORIES.get(r["category"], r["category"])}
            branch = nearest_authority_branch(conn, r["latitude"], r["longitude"])
            item["assigned_authority"] = authority_name_from_location(r["location_label"]) or (branch[1]["name"] if branch else None)
            report_items.append(item)
        return {"reports": report_items, "spots": [dict(s) for s in spots], "branches": [dict(b) for b in branches], "assistance": [dict(a) for a in assistance]}


@app.get("/api/authority/actions")
def authority_actions(authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM alerts WHERE status NOT IN ('surfaced','watch') ORDER BY updated_at DESC LIMIT 100").fetchall()
        return [dict(r) for r in rows]


@app.get("/api/authority/assistance")
def authority_assistance(authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        rows = conn.execute("SELECT * FROM assistance_requests WHERE status='requested' ORDER BY created_at DESC LIMIT 30").fetchall()
        return {"requests": [dict(r) for r in rows]}


@app.get("/api/context-events")
def context_events(authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM context_events ORDER BY start_at DESC")]


@app.post("/api/context-events")
def create_context_event(payload: ContextEventCreate, authorization: str | None = Header(default=None)):
    require_authority(authorization)
    with closing(get_db()) as conn:
        eid = f"CTX-{uuid.uuid4().hex[:8].upper()}"
        spot = get_spot(conn, payload.spot_id)
        ctx_key = f"SPOT:{spot['id']}" if spot else None
        conn.execute("INSERT INTO context_events(id,name,start_at,end_at,location_key) VALUES(?,?,?,?,?)", (eid, payload.name, payload.start_at, payload.end_at, ctx_key))
        for r in conn.execute("SELECT DISTINCT location_key FROM reports").fetchall(): refresh_alert(conn,r["location_key"])
        conn.commit()
        invalidate_summary_cache()
        return {"id": eid, **payload.model_dump()}


@app.post("/api/authority/attack-lab")
def attack_lab(payload: AttackLabScenario, authorization: str | None = Header(default=None)):
    require_authority(authorization)
    base = now(); rows=[]; scenario=payload.scenario
    diversity_target=max(1,round(payload.volume*payload.reporter_diversity/100)); spread=payload.location_spread
    for i in range(payload.volume):
        if scenario=="genuine_slow_build":
            ts=base-timedelta(days=(payload.volume-i)%21, hours=(i*5)%13); tok=f"lab-genuine-{i}"; loc="registered"; category="catcalling"
        elif scenario=="coordinated_flood":
            ts=base-timedelta(minutes=i*0.8); tok=f"lab-burst-{i%max(2,min(3,diversity_target))}"; loc="registered"; category="catcalling"
        elif scenario=="mixed_genuine_coordinated":
            if i < payload.volume*0.6:
                ts=base-timedelta(hours=i*2.2); tok=f"lab-genuine-{i}"; loc="registered"; category="following"
            else:
                j=i-round(payload.volume*0.6); ts=base-timedelta(minutes=j*1.2); tok=f"lab-coord-{j%max(2,min(4,diversity_target))}"; loc="registered"; category="catcalling"
        elif scenario=="patient_spaced_flood":
            ts=base-timedelta(minutes=i*max(11,payload.minutes/max(1,payload.volume))); tok=f"lab-patient-{i%max(2,diversity_target)}"; loc="gps"; category="catcalling"
        elif scenario=="one_reporter_repeat":
            ts=base-timedelta(minutes=i*8); tok="lab-single"; loc="registered"; category="catcalling"
        elif scenario=="festival_event_spike":
            ts=base-timedelta(minutes=i*2); tok=f"lab-event-{i}"; loc="registered"; category="catcalling" if i%3 else "loitering_blocking"
        elif scenario=="cross_spot_corridor":
            ts=base-timedelta(hours=i*2); tok=f"lab-corridor-{i}"; loc="registered" if i%2==0 else "gps"; category="following"
        elif scenario=="post_intervention":
            # First half reflects pre-action activity; second half is deliberately quieter.
            half=max(1,payload.volume//2); j=i if i<half else i-half
            ts=base-timedelta(days=4 if i<half else 1, hours=j*2); tok=f"lab-post-{i}"; loc="registered"; category="unwanted_approach"
        elif scenario=="adaptive_attacker":
            # Vary timing, sources and location labels so the lab tests more than a burst threshold.
            ts=base-timedelta(minutes=(i*17 + (i%5)*3)); tok=f"lab-adaptive-{i%max(4,diversity_target)}"; loc="registered" if i%3 else "gps"; category=("catcalling","following","unwanted_approach")[i%3]
        else: # cold_start
            ts=base-timedelta(days=i%2); tok=f"lab-cold-{i}"; loc="gps"; category="catcalling"
        rows.append({"id":f"LAB-{i}","received_at":ts.isoformat(),"reporter_token":tok,"location_source":loc,"category":category,"location_key":f"LABLOC:{i%max(1,round(1+spread/20))}"})
    groups=[]
    for r in sorted(rows,key=lambda x:x["received_at"]):
        placed=False
        for g in reversed(groups):
            if (datetime.fromisoformat(r["received_at"])-datetime.fromisoformat(g[-1]["received_at"])).total_seconds() <= 15*60 and occurrence_category_compatible(g[-1]["category"],r["category"]):
                g.append(r); placed=True; break
        if not placed: groups.append([r])
    lifetimes={tok:1 for tok in {r["reporter_token"] for r in rows}}
    result=score_votes(rows,groups,lifetimes)
    flags=list(result["integrity_flags"])
    if scenario=="festival_event_spike": flags.append("context event should be checked before interpreting the spike")
    if scenario=="cross_spot_corridor": flags.append("cross-location pattern should be evaluated as a zone/corridor, not one spot")
    if scenario=="post_intervention": flags.append("compare post-action activity with the pre-action period without claiming causality")
    if scenario=="adaptive_attacker": flags.append("adaptive pattern: do not rely on one threshold; inspect time, source and spatial diversity together")
    interpretation={
      "genuine_slow_build":"Multiple sources and separated observations create a sustained signal rather than a single burst.",
      "coordinated_flood":"High volume is preserved as data, but concentrated timing/source structure is surfaced for integrity review rather than treated as proof of false reporting.",
      "mixed_genuine_coordinated":"The scenario deliberately mixes potentially genuine activity with coordinated-looking submissions; human review should inspect the components rather than discard the whole signal.",
      "patient_spaced_flood":"Spacing weakens a simple burst detector, so the lab checks source concentration and episode structure as well.",
      "one_reporter_repeat":"Repeated submissions from one source are decayed and capped; they cannot manufacture independent corroboration.",
      "festival_event_spike":"A contextual event can explain a real spike. The correct response is context review, not automatic suppression.",
      "cold_start":"Sparse local history requires a cautious baseline; venue-class/context priors can support early interpretation without pretending the local baseline is mature.",
      "cross_spot_corridor":"Related activity across adjacent registered locations should be examined as a zone/corridor pattern rather than forced into a single spot.",
      "post_intervention":"Post-action activity is useful for monitoring change, but the system should not claim the action caused the change.",
      "adaptive_attacker":"This scenario varies timing, source diversity and spatial spread to test whether integrity review remains multi-factor rather than threshold-dependent."
    }[scenario]
    return {"scenario":scenario,"raw_reports":payload.volume,"distinct_tokens":result["raw_sources"],"occurrences":len(groups),"effective_signal":result["effective_signal"],"flags":flags,"corroboration":result.get("corroboration",0),"category_diversity":result.get("category_diversity",0),"category_mix":result.get("category_mix",{}),"dominant_category_share":result.get("dominant_category_share",0),"reporter_diversity":payload.reporter_diversity,"location_spread":payload.location_spread,"interpretation":interpretation,"boundary":"The lab evaluates signal influence and integrity patterns. It does not establish whether an anonymous report is true or false, identify a person, or change production data."}


@app.post("/api/demo/reset")
def reset_demo(authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    if officer["role"] != "Station Supervisor":
        raise HTTPException(403, "Supervisor access required for demo reset")
    with closing(get_db()) as conn:
        conn.executescript("DELETE FROM occurrence_reports; DELETE FROM occurrences; DELETE FROM status_history; DELETE FROM alerts; DELETE FROM reports; DELETE FROM assistance_requests; DELETE FROM report_reviews; DELETE FROM report_ai_reviews; DELETE FROM action_evidence; DELETE FROM concern_verifications;")
        conn.commit()
    invalidate_summary_cache()
    return {"status": "reset"}


@app.post("/api/demo/seed")
def seed_demo(authorization: str | None = Header(default=None)):
    officer = require_authority(authorization)
    if officer["role"] != "Station Supervisor":
        raise HTTPException(403, "Supervisor access required for demo seed")
    with closing(get_db()) as conn:
        conn.executescript("DELETE FROM occurrence_reports; DELETE FROM occurrences; DELETE FROM status_history; DELETE FROM alerts; DELETE FROM reports; DELETE FROM assistance_requests; DELETE FROM report_reviews; DELETE FROM report_ai_reviews; DELETE FROM action_evidence; DELETE FROM concern_verifications;")
        conn.execute("DELETE FROM context_events")
        base = now() - timedelta(days=45)
        conn.execute("INSERT INTO context_events(id,name,start_at,end_at,location_key) VALUES(?,?,?,?,?)", ("CTX-DEMO-FEST", "University cultural festival", (base + timedelta(days=40)).isoformat(), (base + timedelta(days=42)).isoformat(), "SPOT:SPOT-042"))
        rows = []
        for i, (day, count) in enumerate([(3,1),(10,1),(32,2),(35,2),(38,2),(40,2)]):
            for j in range(count):
                ts = (base + timedelta(days=day, hours=18 + j*2)).isoformat()
                rows.append((f"RPT-DEMO-{i}-{j}", "SPOT-042", "unwanted_approach", "just_now", "witness", 0, token_digest(f"demo-token-{i}-{j}"), None, ts, 18.5204, 73.8567, "Demo University North Gate", "registered", 1, "SPOT:SPOT-042", 1.0))
        for j in range(24):
            ts = (base + timedelta(days=41, minutes=j*0.3)).isoformat()
            rows.append((f"RPT-BURST-{j}", "SPOT-051", "catcalling", "just_now", "witness", 0, token_digest(f"burst-token-{j%3}"), None, ts, 18.5194, 73.8552, "Civic Transit Gate", "registered", 1, "SPOT:SPOT-051", 1.0))
        # Unregistered GPS location: demonstrates that a location does not need to be pre-registered.
        for j, day in enumerate([8, 17, 25, 31]):
            ts = (base + timedelta(days=day, hours=20)).isoformat()
            rows.append((f"RPT-GEO-{j}", None, "following", "earlier_today", "witness", 0, token_digest(f"geo-demo-{j}"), None, ts, 18.5188, 73.8612, "GPS location near East Corridor", "gps", 1, "GEO:18.519:73.861", 1.0))
        conn.executemany("INSERT INTO reports(id,spot_id,category,happened_when,reporter_type,still_happening,reporter_token,note,received_at,latitude,longitude,location_label,location_source,location_consent,location_key,event_weight) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        for r in rows:
            assign_occurrence(conn, r[0], r[14], r[1], r[2], r[8])
        for key in sorted({r[14] for r in rows}):
            aid = refresh_alert(conn, key)
            if aid:
                conn.execute("UPDATE reports SET alert_id=? WHERE location_key=? AND alert_id IS NULL", (aid, key))
        conn.commit()
    invalidate_summary_cache()
    return {"status": "seeded"}
