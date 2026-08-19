"""Data-leak watch: email exposure monitoring for the IRIS group "veille-data-leak".

Every member of that IRIS group with a valid email address is checked
periodically against XposedOrNot (free, no API key: https://xposedornot.com).
A NEW breach — one not already reported for that email — opens an IRIS case
tagged "data-leak", built with its OWN report template (a person's exposure to
a data leak has nothing to do with a compromised machine: no asset, no
timeline, a different narrative). Re-detecting a breach already reported only
refreshes the note, it never reopens a second case.

Design choices, mirroring vt.py's filter (same "external API + Postgres
cache" shape):

- **The watchlist lives in IRIS, not here.** Group membership and email are
  IRIS platform-user data (`dfir_iris_client.admin.AdminHelper`); this module
  only reads them. Managing WHO is watched is therefore an IRIS admin action
  (add the user to the group "veille-data-leak"), not a soc-agent one. The
  group itself IS created here, unconditionally, as long as
  `DATA_LEAK_MONITORING` is on — without it existing, an analyst has nowhere
  to add a user before the first run ever happens.
- **Cache mandatory, keyed on the email.** XposedOrNot's public quota (2
  req/s, 25/h, 100/day) is shared with every anonymous caller behind our IP.
  `data_leak_email_check.signature` is a hash of the breach names found: the
  case is (re)opened only when it CHANGES, so an old, still-present breach is
  never replayed into a new case every day.
- **Best-effort everywhere past the network call.** A case wrongly classified
  or tagged is still a case an analyst sees; a raised exception here must
  never lose that.

    python -m soc_agent.data_leak             # one pass
    python -m soc_agent.data_leak --email foo@example.com   # force one check
"""

import argparse
import hashlib
import json
import logging
import re
import time

import psycopg
import requests
from psycopg.rows import dict_row

from . import config
from .iris import CLASSIF_DEFAULT, _case_exists, _client, _severity_id, _set_note, _tag

log = logging.getLogger("data_leak")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Advisory lock: distinct from every other job's (cf. retention.py, mitigate.py,
# training.py, whitelist_task.py, archive.py, cycle.py for the taken values).
_LOCK_DATA_LEAK = 0x50CA7

DIR_LEAK = "Fuite de données"
TAG_DATA_LEAK = "data-leak"

FIELD_SEVERITY = "severity_id"
SEV_MEDIUM, SEV_HIGH = "Medium", "High"


# --------------------------------------------------------------------------
# IRIS: watchlist (group "veille-data-leak") and case
# --------------------------------------------------------------------------

def _admin():
    from dfir_iris_client.admin import AdminHelper
    from dfir_iris_client.session import ClientSession
    session = ClientSession(apikey=config.IRIS_API_KEY, host=config.IRIS_URL,
                            ssl_verify=config.IRIS_VERIFY_TLS)
    return AdminHelper(session)


def _ensure_group(admin) -> None:
    """Create `config.DATA_LEAK_GROUP_NAME` if it is not there yet.

    Called on EVERY pass, not once at install time: as long as
    DATA_LEAK_MONITORING stays on, the group it depends on must exist even if
    it was deleted by hand or this is the very first run. No permission
    granted (`group_permissions=[]`): this group only marks who is watched, it
    must not itself widen anyone's IRIS access.
    """
    g = admin.get_group(config.DATA_LEAK_GROUP_NAME)
    if g.is_success():
        return
    r = admin.add_group(
        group_name=config.DATA_LEAK_GROUP_NAME,
        group_description="Veille data-leak : membres dont l'email est "
                          "vérifié contre XposedOrNot (soc_agent.data_leak).",
        group_permissions=[])
    if r.is_success():
        log.info("IRIS group \"%s\" created", config.DATA_LEAK_GROUP_NAME)
    else:
        log.warning("IRIS group \"%s\" creation failed: %s",
                    config.DATA_LEAK_GROUP_NAME, r.get_msg())


def _group_member_ids(group_data: dict) -> list[int]:
    """User ids of a group's members. Tolerant to the exact server shape:
    either a bare list of ids or a list of {"user_id": ...} objects.
    """
    members = group_data.get("group_members") or group_data.get("members") or []
    ids: list[int] = []
    for m in members:
        raw = (m.get("user_id") or m.get("id")) if isinstance(m, dict) else m
        try:
            ids.append(int(raw))
        except (TypeError, ValueError):
            continue
    return ids


def watchlist() -> list[dict]:
    """Members of `config.DATA_LEAK_GROUP_NAME` with a syntactically valid email.

    Returns a list of {"user_id", "login", "email"}. Best-effort: a member
    whose lookup fails yields fewer entries rather than an exception — this
    runs unattended. The group itself is created if missing (`_ensure_group`).
    """
    admin = _admin()
    _ensure_group(admin)
    try:
        g = admin.get_group(config.DATA_LEAK_GROUP_NAME)
    except Exception as e:  # noqa: BLE001
        log.warning("IRIS group \"%s\" unreadable: %s",
                    config.DATA_LEAK_GROUP_NAME, e)
        return []
    if not g.is_success():
        log.warning("IRIS group \"%s\" not found: %s",
                    config.DATA_LEAK_GROUP_NAME, g.get_msg())
        return []

    out: list[dict] = []
    for uid in _group_member_ids(g.get_data() or {}):
        try:
            u = admin.get_user(uid)
        except Exception as e:  # noqa: BLE001
            log.debug("IRIS user #%s unreadable: %s", uid, e)
            continue
        if not u.is_success():
            continue
        data = u.get_data() or {}
        email = (data.get("user_email") or "").strip().lower()
        if email and _EMAIL_RE.match(email):
            out.append({"user_id": uid, "login": data.get("user_login") or "",
                        "email": email})
    return out


def _tag_case(case, case_id: int, email: str) -> None:
    """Union-add the "data-leak" + email tags. Reuses iris._tag: it already
    does read-union-write on `case_tags`, generic enough for any tag pair.
    """
    _tag(case, case_id, TAG_DATA_LEAK, email)


def _set_severity(case, case_id: int, name: str) -> None:
    sid = _severity_id(case, name)
    if sid is None:
        log.warning("severity \"%s\" unknown to the IRIS server: case #%s "
                    "left as is", name, case_id)
        return
    try:
        case._s.pi_post(f"/manage/cases/update/{case_id}",
                        data={FIELD_SEVERITY: sid})
    except Exception as e:  # noqa: BLE001
        log.debug("severity update on case #%s: %s", case_id, e)


def _note_content(email: str, login: str, breaches: list[str],
                    analytics: dict | None) -> str:
    lines = [
        f"# Fuite de données — {email}",
        "",
        f"Compte IRIS : `{login}`" if login else "",
        "Détecté via XposedOrNot (xposedornot.com).",
        "",
        f"## Fuites connues ({len(breaches)})",
        "",
    ]
    lines += [f"- {b}" for b in breaches] or ["- (aucun nom de fuite renvoyé)"]

    if analytics:
        pw = ((analytics.get("BreachMetrics") or {}).get("passwords_strength")
              or [{}])[0]
        if pw:
            lines += [
                "",
                "## Robustesse des mots de passe exposés",
                "",
                f"- En clair : {pw.get('PlainText', 0)}",
                f"- Faciles à casser : {pw.get('EasyToCrack', 0)}",
                f"- Hash fort : {pw.get('StrongHash', 0)}",
                f"- Inconnu : {pw.get('Unknown', 0)}",
            ]
        risk = ((analytics.get("BreachMetrics") or {}).get("risk") or [{}])[0]
        if risk:
            lines += ["", f"**Score de risque XposedOrNot : "
                      f"{risk.get('risk_label', '?')} "
                      f"({risk.get('risk_score', '?')}/10)**"]

    lines += [
        "",
        "## Actions recommandées",
        "",
        "- Changer le mot de passe du compte concerné (et partout où il était "
        "réutilisé)",
        "- Activer la MFA si ce n'est pas déjà fait",
        "- Vérifier l'absence d'activité suspecte sur les services listés",
    ]
    return "\n".join(l for l in lines if l is not None)


def _severity_name(analytics: dict | None) -> str:
    """High if a weak/plaintext password is confirmed exposed, else Medium.

    Best-effort: `breach-analytics`'s exact schema is loosely documented, a
    missing or reshaped field must fall back to Medium, never raise.
    """
    try:
        pw = ((analytics or {}).get("BreachMetrics") or {}).get(
            "passwords_strength") or [{}]
        weak = int(pw[0].get("PlainText", 0)) + int(pw[0].get("EasyToCrack", 0))
        if weak > 0:
            return SEV_HIGH
    except Exception:  # noqa: BLE001
        pass
    return SEV_MEDIUM


def _open_or_refresh_case(conn, email: str, login: str, breaches: list[str],
                            analytics: dict | None,
                            existing_case_id: int | None) -> int:
    case = _client()
    content = _note_content(email, login, breaches, analytics)
    severity = _severity_name(analytics)

    if existing_case_id and _case_exists(case, existing_case_id):
        _set_note(case, existing_case_id, "Fuite détectée", content,
                  directory=DIR_LEAK)
        _tag_case(case, existing_case_id, email)
        _set_severity(case, existing_case_id, severity)
        log.info("case #%s refreshed: %d breach(es) for %s",
                 existing_case_id, len(breaches), email)
        return existing_case_id

    r = case.add_case(
        case_name=f"Fuite de données — {email}",
        case_description=f"Exposition détectée par la veille data-leak pour "
                         f"{email} ({len(breaches)} fuite(s)).",
        case_customer=config.IRIS_CUSTOMER,
        case_classification=config.DATA_LEAK_CLASSIFICATION_ID or CLASSIF_DEFAULT,
        soc_id=f"Aura-DataLeak-{email}",
    )
    if not r.is_success():
        raise RuntimeError(f"data-leak case creation failed for {email}: "
                          f"{r.get_msg()}")
    case_id = r.get_data()["case_id"]
    _tag_case(case, case_id, email)
    _set_severity(case, case_id, severity)
    _set_note(case, case_id, "Fuite détectée", content, directory=DIR_LEAK)
    try:
        case.add_ioc(value=email, ioc_type="Email",
                    description="Compte surveillé — veille data-leak",
                    cid=case_id)
    except Exception as e:  # noqa: BLE001 — an unknown IOC type must not fail
        log.debug("data-leak IOC skipped for %s: %s", email, e)
    log.info("case #%s opened: %d breach(es) for %s", case_id, len(breaches),
             email)
    return case_id


# --------------------------------------------------------------------------
# XposedOrNot
# --------------------------------------------------------------------------

def _query_check(email: str) -> list[str] | None:
    """Breach names for `email`, [] if none, None if the call must be retried."""
    try:
        r = requests.get(f"{config.DATA_LEAK_XON_URL}/v1/check-email/{email}",
                         timeout=20)
    except requests.RequestException as e:
        log.warning("XposedOrNot unreachable for %s: %s", email, e)
        return None
    if r.status_code == 429:
        log.info("XposedOrNot quota reached (429) — stopping for this pass")
        return None
    if r.status_code != 200:
        log.warning("XposedOrNot %s for %s", r.status_code, email)
        return None
    data = r.json()
    if "Error" in data or not data.get("breaches"):
        return []
    # "breaches" is a list containing one list of names.
    names = data["breaches"][0] if data["breaches"] else []
    return [str(n) for n in names]


def _query_analytics(email: str) -> dict | None:
    """Best-effort detail call. None on any failure — never blocks the case."""
    try:
        r = requests.get(f"{config.DATA_LEAK_XON_URL}/v1/breach-analytics",
                         params={"email": email}, timeout=20)
        if r.status_code != 200:
            return None
        return r.json()
    except (requests.RequestException, ValueError) as e:
        log.debug("XposedOrNot analytics skipped for %s: %s", email, e)
        return None


def _signature(breaches: list[str]) -> str:
    return hashlib.sha256(
        ",".join(sorted(breaches)).encode()).hexdigest()


def _read_cache(conn, email: str) -> dict | None:
    return conn.execute(
        "SELECT * FROM data_leak_email_check WHERE email = %s", (email,)
    ).fetchone()


def _write_cache(conn, email: str, login: str, breaches: list[str],
                   signature: str, case_id: int | None) -> None:
    conn.execute(
        """INSERT INTO data_leak_email_check
             (email, user_login, breaches, signature, iris_case_id, checked_at)
           VALUES (%s,%s,%s,%s,%s, now())
           ON CONFLICT (email) DO UPDATE SET
             user_login=EXCLUDED.user_login, breaches=EXCLUDED.breaches,
             signature=EXCLUDED.signature,
             iris_case_id=COALESCE(EXCLUDED.iris_case_id,
                                    data_leak_email_check.iris_case_id),
             checked_at=now()""",
        (email, login, json.dumps(breaches), signature, case_id))


# --------------------------------------------------------------------------

def check_one(conn, email: str, login: str = "") -> dict:
    """Check a single email, open/refresh a case if a NEW breach appeared."""
    breaches = _query_check(email)
    if breaches is None:
        return {"email": email, "state": "retry"}
    signature = _signature(breaches)
    cached = _read_cache(conn, email)
    prior_signature = cached["signature"] if cached else ""
    case_id = cached["iris_case_id"] if cached else None

    if breaches and signature != prior_signature:
        analytics = _query_analytics(email)
        try:
            case_id = _open_or_refresh_case(conn, email, login, breaches,
                                             analytics, case_id)
        except Exception as e:  # noqa: BLE001 — the cache must still be
            # written (avoids retrying the same XposedOrNot call every pass);
            # the case creation failure is logged, not swallowed silently.
            log.error("IRIS case for %s: %s", email, e)
    _write_cache(conn, email, login, breaches, signature, case_id)
    conn.commit()
    return {"email": email, "state": "new_leak" if signature != prior_signature
            and breaches else "unchanged", "breach_count": len(breaches)}


def run() -> dict:
    if not config.DATA_LEAK_MONITORING:
        return {"state": "disabled"}
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        if not conn.execute("SELECT pg_try_advisory_lock(%s)",
                            (_LOCK_DATA_LEAK,)
                            ).fetchone()["pg_try_advisory_lock"]:
            log.info("data-leak: pass already running, skipping this round")
            return {"state": "locked"}
        try:
            members = watchlist()
            log.info("data-leak: %d watched email(s) in group \"%s\"",
                     len(members), config.DATA_LEAK_GROUP_NAME)
            results = []
            calls = 0
            for m in members:
                if calls >= config.DATA_LEAK_MAX_LOOKUPS:
                    log.info("data-leak: lookup cap reached (%d), rest "
                             "deferred to next pass",
                             config.DATA_LEAK_MAX_LOOKUPS)
                    break
                if calls:
                    time.sleep(1)  # stay under XposedOrNot's 2 req/s
                res = check_one(conn, m["email"], m["login"])
                calls += 1
                results.append(res)
                if res["state"] == "retry":
                    break  # quota/network hit: stop cleanly, retry next pass
            new_leaks = sum(1 for r in results if r["state"] == "new_leak")
            if new_leaks:
                log.info("data-leak: %d new leak(s) reported", new_leaks)
            return {"state": "ok", "checked": len(results),
                    "new_leaks": new_leaks}
        finally:
            # Rollback before unlock: an aborted transaction refuses every
            # command, including the unlock (cf. retention.py/archive.py).
            for step in (conn.rollback,
                          lambda: conn.execute(
                              "SELECT pg_advisory_unlock(%s)",
                              (_LOCK_DATA_LEAK,))):
                try:
                    step()
                except Exception as e:  # noqa: BLE001
                    log.debug("releasing the data-leak lock: %s", e)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser()
    p.add_argument("--email", help="Force-check a single email (bypasses the "
                                    "IRIS group and the lookup cap)")
    args = p.parse_args()
    if args.email:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as c:
            print(check_one(c, args.email.strip().lower()))
    else:
        print(run())
