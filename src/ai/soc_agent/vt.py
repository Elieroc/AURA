"""VirusTotal filter for legitimate executables, BEFORE correlation.

Goal: a clean executable (Sysmon, FIM, VT integration) must neither weigh in a
case nor open one when it is the only event. We check the binary's HASH against
the VirusTotal reputation; if VT knows it and no engine judges it malicious, the
alert carrying it is marked `suppressed` — hence excluded from correlation
(`correlate` filters on `NOT suppressed`), exactly like the noise filter.

Design choices:

- **Deterministic, not the LLM.** VT reputation is hard data; the decision not to
  open a case on a clean binary does not go through the model.
- **Deliberately narrow scope.** We only filter executables dropped outside the
  system directories. A signed System32 binary (`powershell.exe`,
  `certutil.exe`...) is "clean" to VT but can be abused (LOLBin): there,
  detection is behavioural, not file-based — we leave it alone.
- **When in doubt, keep.** A hash unknown to VT (404) or seen by too few engines
  is NOT legitimate: verdict `unknown`, no suppression.
- **Cache mandatory.** The public API is capped (4 req/min, 500/day): verdicts
  are cached (`vt_file_reputation`, TTL `VT_CACHE_TTL_DAYS`) and the number of
  network calls per pass is bounded (`VT_MAX_LOOKUPS`). The rest is retried on
  the next cycle.
- **Auditable and reversible.** `suppress_reason` carries the VT stats; a
  re-ingest re-evaluates. A hash that later turns malicious is no longer
  filtered.
"""
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import psycopg
import requests
from psycopg.rows import dict_row

from . import config

log = logging.getLogger("vt")

# "SHA256=ABCD...,MD5=...,IMPHASH=..." (Sysmon eventdata.hashes) -> dict.
_RE_HASH_KV = re.compile(r"(SHA256|SHA1|MD5)=([0-9A-Fa-f]+)")
_RE_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RE_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_RE_MD5 = re.compile(r"^[0-9a-f]{32}$")


def _path(data: dict, raw: dict) -> str:
    """Path of the executable at stake (for the "dropped outside system" scope)."""
    win = (data.get("win") or {}).get("eventdata") or {}
    audit = data.get("audit") or {}
    sc = raw.get("syscheck") or {}
    return str(win.get("image") or audit.get("exe")
              or (audit.get("file") or {}).get("name")
              or sc.get("path") or raw.get("entity") or "")


def _hash(data: dict, raw: dict) -> str | None:
    """File hash of the alert, lowercase. sha256 > sha1 > md5.

    Sources: Sysmon `data.win.eventdata.hashes`, FIM `syscheck.*_after`, VT
    integration `data.virustotal.source.*`.
    """
    found: dict[str, str] = {}

    win = (data.get("win") or {}).get("eventdata") or {}
    for algo, val in _RE_HASH_KV.findall(str(win.get("hashes") or "")):
        found[algo.lower()] = val.lower()

    sc = raw.get("syscheck") or {}
    for algo in ("sha256", "sha1", "md5"):
        v = sc.get(f"{algo}_after") or sc.get(algo)
        if v:
            found.setdefault(algo, str(v).lower())

    vt = (data.get("virustotal") or {}).get("source") or {}
    for algo in ("sha256", "sha1", "md5"):
        if vt.get(algo):
            found.setdefault(algo, str(vt[algo]).lower())

    for algo, rx in (("sha256", _RE_SHA256), ("sha1", _RE_SHA1), ("md5", _RE_MD5)):
        h = found.get(algo)
        if h and rx.match(h):
            return h
    return None


def _outside_system(path: str) -> bool:
    """True if the executable is NOT in a system directory (hence filterable)."""
    # The Windows eventchannel doubles the backslashes (C:\\\\Windows\\\\...):
    # fold them back to one, otherwise the system prefix never matches and a
    # clean System32 LOLBin (net1.exe...) is wrongly suppressed.
    p = path.lower().replace("\\\\", "\\")
    if not p:
        return False
    return not p.startswith(config.VT_DIRS_SYSTEM)


def _verdict(stats: dict, total: int) -> str:
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal > 0 or sus > 0:
        return "malicious"
    if total >= config.VT_MIN_ENGINES:
        return "legit"
    return "unknown"


def _read_cache(conn, h: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM vt_file_reputation WHERE sha256 = %s", (h,)).fetchone()
    if not row:
        return None
    age = datetime.now(timezone.utc) - row["checked_at"]
    if age > timedelta(days=config.VT_CACHE_TTL_DAYS):
        return None          # stale: we will call VT again
    return row


def _query_vt(h: str) -> dict | None:
    """VT network call. None when we must retry later (429 / network error)."""
    try:
        r = requests.get(
            f"{config.VT_URL}/files/{h}",
            headers={"x-apikey": config.VT_API_KEY}, timeout=20)
    except requests.RequestException as e:
        log.warning("VT unreachable for %s: %s", h[:12], e)
        return None
    if r.status_code == 404:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "total": 0, "verdict": "unknown", "permalink": None}
    if r.status_code == 429:
        log.info("VT quota reached (429) — stopping for this pass")
        return None
    if r.status_code != 200:
        log.warning("VT %s for %s", r.status_code, h[:12])
        return None
    attrs = (r.json().get("data") or {}).get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(int(v) for v in stats.values())
    return {
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "total": total,
        "verdict": _verdict(stats, total),
        "permalink": f"https://www.virustotal.com/gui/file/{h}",
    }


def _write_cache(conn, h: str, rep: dict) -> None:
    conn.execute(
        """INSERT INTO vt_file_reputation
             (sha256, malicious, suspicious, harmless, undetected, total,
              verdict, permalink, checked_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s, now())
           ON CONFLICT (sha256) DO UPDATE SET
             malicious=EXCLUDED.malicious, suspicious=EXCLUDED.suspicious,
             harmless=EXCLUDED.harmless, undetected=EXCLUDED.undetected,
             total=EXCLUDED.total, verdict=EXCLUDED.verdict,
             permalink=EXCLUDED.permalink, checked_at=now()""",
        (h, rep["malicious"], rep["suspicious"], rep["harmless"],
         rep["undetected"], rep["total"], rep["verdict"], rep["permalink"]))


def filter(conn: psycopg.Connection | None = None) -> int:
    """Marks `suppressed` the alerts carrying an executable VT judges legitimate.

    Returns the number of alerts suppressed. Without a VT key, does nothing.
    """
    if not config.VT_API_KEY:
        return 0
    if conn is None:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as c:
            return filter(c)

    # Candidates: uncorrelated, not suppressed, significant level.
    lines = conn.execute(
        """SELECT id, rule_level, raw FROM alerts
            WHERE incident_id IS NULL AND NOT suppressed AND rule_level >= %s
            ORDER BY ts DESC""",
        (config.VT_EXE_MIN_LEVEL,)).fetchall()

    # hash -> [alert ids], keeping only the executables outside the system.
    by_hash: dict[str, list[str]] = {}
    for r in lines:
        raw = r["raw"]
        data = raw.get("data") or {}
        h = _hash(data, raw)
        if not h:
            continue
        if not _outside_system(_path(data, raw)):
            continue
        by_hash.setdefault(h, []).append(r["id"])
    if not by_hash:
        return 0

    calls = 0
    suppressed = 0
    for h, ids in by_hash.items():
        rep = _read_cache(conn, h)
        if rep is None:
            if calls >= config.VT_MAX_LOOKUPS:
                continue                 # network cap reached, next cycle
            if calls:
                # Close the transaction BEFORE sleeping. `_read_cache` opened
                # one, and psycopg does not close it by itself: without this
                # commit the session stays "idle in transaction" for the whole
                # pause. With VT_MAX_LOOKUPS calls that is tens of minutes of
                # locks held for nothing — on 2026-08-11, two cycle sessions
                # blocked for 19 min brought ingestion to a halt and made a
                # migration ALTER TABLE fail.
                conn.commit()
                time.sleep(16)           # public API: 4 req/min
            rep = _query_vt(h)
            calls += 1
            if rep is None:
                break                    # 429 / network: stop cleanly
            _write_cache(conn, h, rep)
            conn.commit()

        if rep["verdict"] != "legit":
            continue
        reason = (f"vt_legit_exe: 0/{rep['total']} positive engines "
                  f"(harmless={rep['harmless']}) {rep.get('permalink') or ''}").strip()
        n = conn.execute(
            """UPDATE alerts SET suppressed = true, suppress_reason = %s
                WHERE id = ANY(%s) AND NOT suppressed AND incident_id IS NULL""",
            (reason, ids)).rowcount
        conn.commit()
        if n:
            suppressed += n
            log.info("VT: %d alert(s) suppressed, legitimate exe %s (0/%d)",
                     n, h[:12], rep["total"])
    if suppressed:
        log.info("VT: %d alert(s) dropped (legitimate executables), "
                 "%d network call(s)", suppressed, calls)
    return suppressed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"{filter()} alert(s) suppressed")
