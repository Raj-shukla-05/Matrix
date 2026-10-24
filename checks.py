"""JobShield checks: known-scam database (SQLite), domain helpers and live WHOIS domain age."""
import datetime
import os
import re
import sqlite3
import threading

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "jobshield.db")

# Demo seed only. These are synthetic entries so the demo works offline.
# Real entries are added through the "Report this scam" button in the app.
SEED = [
    ("domain", "quick-earn-jobs.xyz", "demo seed: fake earning portal"),
    ("domain", "upgovt-jobs.online", "demo seed: fake government job portal"),
    ("email", "hr.infosys.careers@gmail.com", "demo seed: fake Infosys HR mail"),
    ("email", "tcs.recruitment2026@yahoo.com", "demo seed: fake TCS HR mail"),
    ("phone", "9876543210", "demo seed: reported for registration fee fraud"),
    ("phone", "9123456780", "demo seed: reported for security deposit fraud"),
]

TWO_PART_SLD = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}


def _connect(path=None):
    return sqlite3.connect(path or DB_PATH)


def init_db(path=None):
    con = _connect(path)
    con.execute(
        "CREATE TABLE IF NOT EXISTS scams ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL, "
        "note TEXT, added TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(kind, value))"
    )
    con.executemany("INSERT OR IGNORE INTO scams(kind, value, note) VALUES (?,?,?)", SEED)
    con.commit()
    con.close()


def normalize(kind, value):
    value = value.strip().lower()
    if kind == "phone":
        digits = re.sub(r"\D", "", value)
        return digits[-10:]
    return value


def add_report(kind, value, note="user report", path=None):
    init_db(path)
    value = normalize(kind, value)
    if not value:
        return False
    con = _connect(path)
    con.execute("INSERT OR IGNORE INTO scams(kind, value, note) VALUES (?,?,?)", (kind, value, note))
    con.commit()
    con.close()
    return True


def lookup(kind, values, path=None):
    """Return list of (value, note) for values that exist in the scam database."""
    init_db(path)
    hits = []
    con = _connect(path)
    for v in values:
        nv = normalize(kind, v)
        if not nv:
            continue
        row = con.execute("SELECT note FROM scams WHERE kind=? AND value=?", (kind, nv)).fetchone()
        if row:
            hits.append((nv, row[0]))
    con.close()
    return hits


def count(path=None):
    init_db(path)
    con = _connect(path)
    n = con.execute("SELECT COUNT(*) FROM scams").fetchone()[0]
    con.close()
    return n


def get_all_reports(limit=50, path=None):
    init_db(path)
    con = _connect(path)
    rows = con.execute("SELECT kind, value, note, added FROM scams ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    con.close()
    return rows


def search_database(query: str, path=None):
    """Search for a contact, domain, or keyword in the community scam database."""
    if not query or not query.strip():
        return []
    init_db(path)
    q = query.strip().lower()
    q_digits = re.sub(r"\D", "", q)
    con = _connect(path)
    params = [f"%{q}%", f"%{q}%"]
    sql = "SELECT kind, value, note, added FROM scams WHERE value LIKE ? OR note LIKE ?"
    if len(q_digits) >= 6:
        sql += " OR (kind='phone' AND value LIKE ?)"
        params.append(f"%{q_digits[-10:]}%")
    rows = con.execute(sql, params).fetchall()
    con.close()
    return rows


def registrable(domain):
    """Rough registrable domain: example.co.in -> example.co.in, mail.example.com -> example.com."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in TWO_PART_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(domain_a, domain_b):
    return registrable(domain_a) == registrable(domain_b)


def _rdap_age(domain, timeout=5):
    """RDAP over HTTPS (works on networks that block WHOIS port 43). Returns (status, age_days)."""
    try:
        import requests
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=timeout,
                         headers={"Accept": "application/rdap+json"})
    except Exception:
        return "neterr", None
    if r.status_code != 200:
        return "nodata", None
    try:
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                created = datetime.datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                now = datetime.datetime.now(datetime.timezone.utc)
                if created.tzinfo is None:
                    created = created.replace(tzinfo=datetime.timezone.utc)
                return "ok", max((now - created).days, 0)
    except Exception:
        pass
    return "nodata", None


def domain_age_days(domain, timeout=6):
    """Domain age in days (RDAP first, WHOIS as fallback), or None if offline or unavailable."""
    status, age = _rdap_age(domain)
    if status == "ok":
        return age
    if status == "neterr":
        return None  # internet is down, WHOIS would only add a long wait
    try:
        import whois  # python-whois
    except Exception:
        return None
    box = {}

    def work():
        try:
            rec = whois.whois(domain)
            created = rec.creation_date
            if isinstance(created, list):
                created = created[0]
            box["created"] = created
        except Exception:
            pass

    t = threading.Thread(target=work, daemon=True)
    t.start()
    t.join(timeout)
    created = box.get("created")
    if not isinstance(created, datetime.datetime):
        return None
    now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    if created.tzinfo is not None:
        created = created.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    return max((now - created).days, 0)
