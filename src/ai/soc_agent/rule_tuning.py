"""Automatic tuning of Wazuh rules from recurring false positives.

The second stage of the closed loop, complementary to `whitelist.py` — not a
replacement:

- `whitelist.py` writes into `whitelist_rules`, read by `noise.py`. The alert is
  produced by the manager, indexed, then dropped by the soc-agent. The noise is
  filtered LATE: it has already cost a rule evaluation, a disk write and an
  indexing.
- this module drops the noise AS EARLY AS POSSIBLE, inside the rule engine
  itself: the generated child rule carries a low level (or 0), hence no more
  alert at a useful level, no indexing, no correlation. That is what the
  platform load calls for.

It can do both things:

- **lower the severity** (default, `RULE_TUNING_LEVEL`): the alert still exists,
  it simply drops below the incident-opening threshold. We keep the trace and
  lose the noise. That is the safe mode, and the one that answers "do not
  invalidate the rule";
- **suppress** (level 0): no alert at all. Reserved, locked behind
  `RULE_TUNING_ALLOW_LEVEL_0`.

The generated rules live in `RULE_TUNING_DIR`, one file per rule, with the same
conventions as the hand-written rules (see rules/README.md). The directory is
also the STATE: a signature already handled has its file, we do not handle it
again. No extra table to migrate, and what the manager sees is exactly what is
authoritative.

    python -m soc_agent.rule_tuning               # analyse, apply, verify
    python -m soc_agent.rule_tuning --simulation  # shows the XML, touches nothing
    python -m soc_agent.rule_tuning --list        # generated rules

## Why the proof is empirical and not "by construction"

Translating a signature into XML conditions requires guessing the field name as
the rule engine sees it (`<user>` for srcuser, `<field name="audit.exe">` for an
auditd path, `<field name="file">` for FIM...). That mapping table is fragile and
depends on the decoder.

So we do not bet on it. Every generated rule is PROVEN by a real replay through
the manager's `/logtest` API, before and after loading:

1. before: the FP event does fall on the parent rule, at the expected level;
2. before: a COUNTER-EXAMPLE — an event of the SAME parent rule with a DIFFERENT
   value on the discriminant field — also falls on the parent;
3. after loading: the FP event falls on the generated rule, at the target level;
4. after loading: the counter-example STILL falls on the parent, at its original
   level.

Step 4 is the heart of the "the whitelist must not invalidate the rule"
guardrail: it checks on real traffic that the original detection still works for
everything that is not the exonerated signature. If a single check fails, the
file is removed and the manager reloaded — we are back to the previous state. A
wrong field name therefore cannot produce a silent exception: it produces a
refusal.

Without a counter-example available in database, we REFUSE: an exception that
cannot be proven harmless is not deployed.

## Guardrails (the same as the whitelist, plus two)

- PRECISE signature: `rule_id` alone is refused, at least one discriminant field
  is needed (account, command, file, URL);
- never above `WHITELIST_MAX_LEVEL`;
- never a signature seen at least once as `true_positive`;
- ANCHORED conditions (`^value$`, pcre2, escaped value): an exception on
  `/tmp/build.sh` cannot cover `/tmp/build.sh.evil`;
- the number of generated rules is capped (`RULE_TUNING_MAX_RULES`).
"""

from __future__ import annotations

import argparse
import json
import re
import time
from pathlib import Path
from xml.sax.saxutils import escape

import psycopg
import requests
from psycopg.rows import dict_row

from . import config
from .noise import FIELD, FILE_PATHS, _read, _value_field
from .whitelist import (DISCRIMINANT_FIELDS, _canonical, _incidents_by_verdict)

requests.packages.urllib3.disable_warnings()  # self-signed certificates locally


# Signature field -> Wazuh rule option mapping. A starting point only: what
# decides is the logtest replay (see the module docstring).
#
# `srcuser` has NO `<field name="srcuser">` form: it is a static field of the
# engine, and it raises "Field 'srcuser' is static" at load time. Its dedicated
# option is `<user>`.
_OPTION_STATIC = {
    "src_user": "user",
    "dst_user": "user",
    "url": "url",
}

# Discriminants accepted here, one more than the post-retrieval whitelist:
# `url`. It is THE field of web false positives, and by far the biggest
# contributor to load on this platform (a reverse proxy exposed to the
# internet). The post-retrieval filter can do nothing useful with it — the alert
# is already produced and indexed when it runs; a child rule can.
RULE_DISCRIMINANT_FIELDS = DISCRIMINANT_FIELDS + ("url",)
# JSON path (data.X) -> dynamic field name as written in a rule. Wazuh names
# the dynamic field by its path UNDER `data.`.
_PREFIX_DATA = "data."
# syscheck is apart: the field is exposed as `file` in the FIM rules.
_FIELD_SYSCHECK = {"syscheck.path": "file"}

_RE_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str, size: int = 40) -> str:
    return _RE_SLUG.sub("-", str(text).lower()).strip("-")[:size] or "signature"


# What an XML comment cannot contain without ceasing to be a comment: `--`
# (illegal per the spec) and `<`/`>` (which allow escaping it). Control
# characters are dropped too — they serve to hide text from a human reader.
_RE_OUTSIDE_COMMENT = re.compile(r"-{2,}|[<>\x00-\x08\x0b-\x1f\x7f]")


# Characters an XML 1.0 document cannot carry, even escaped: every control
# character but tab, carriage return and line feed.
_RE_XML_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _commentable(value, size: int = 200) -> str:
    """Value made harmless inside an XML comment.

    The signature values (`command`, `file`, `url`, `src_user`) are written by
    the monitored machines, hence possibly by an attacker. They do NOT go through
    `saxutils.escape` here, and they should not: `escape` does not handle `--`,
    which is enough to close an XML comment.

    Without this neutralisation, a URL containing `-->` closed the header comment
    and the rest of the value became XML interpreted by the manager — that is,
    the injection of an arbitrary rule into the detection engine, loaded at the
    next restart. The `url` field is the worst case: it is the biggest
    contributor of false positives on this platform, and it is entirely chosen by
    the client hitting the reverse proxy.
    """
    text = _RE_OUTSIDE_COMMENT.sub("_", str(value)).replace("\n", " ")
    return text[:size]


# --- building the conditions -------------------------------------------------

def _file_path(raw: dict) -> str | None:
    """Concrete JSON path the virtual "file" field comes from for THIS raw doc.

    "file" has no single location (syscheck, VirusTotal, auditd...). To write a
    rule condition the real path is needed, not the virtual field.
    """
    for path in FILE_PATHS:
        if _read(raw, path):
            return path
    return None


def _condition(field: str, value: str, raw: dict) -> str | None:
    """One XML condition line for a signature field, or None.

    Anchored (`^...$`) and escaped: an exception must cover ONLY the observed
    value. Without anchoring, `<field name="command">rm</field>` would exonerate
    any command containing "rm".

    A value carrying a character forbidden by XML 1.0 is REFUSED (None):
    `escape()` does not handle them, and the file produced would be unreadable by
    the rule engine. The effect would not be silent but expensive — analysisd
    refuses to start, `_restart` fails, the whole batch is removed and the
    manager restarts a second time. Refusing upstream is better.
    """
    if _RE_XML_FORBIDDEN.search(value):
        return None
    pattern = f"^{re.escape(value)}$"
    option = _OPTION_STATIC.get(field)
    if option:
        return f'    <{option} type="pcre2">{escape(pattern)}</{option}>'

    if field == "file":
        path = _file_path(raw)
        if not path:
            return None
        name = _FIELD_SYSCHECK.get(path) or path.removeprefix(_PREFIX_DATA)
    else:
        path = FIELD.get(field, field)
        name = path.removeprefix(_PREFIX_DATA)

    return (f'    <field name="{escape(name)}" type="pcre2">'
            f'{escape(pattern)}</field>')


def build_xml(rule_id: int, parent: str, level: int, signature: dict,
                   raw: dict, n_fp: int, incidents: list[int]) -> str | None:
    """XML of the child rule, or None when the signature is not translatable."""
    conditions = []
    for field in RULE_DISCRIMINANT_FIELDS:
        if field in signature:
            line = _condition(field, signature[field], raw)
            if line is None:
                return None
            conditions.append(line)
    if not conditions:
        return None

    if level == 0:
        effect = ("Suppression: no alert is produced any more for THIS "
                  "signature. The parent rule stays whole for everything else.")
    else:
        effect = (f"Severity lowered to {level}: the alert still exists and "
                  "stays readable, it simply drops below the incident-opening "
                  "threshold. The parent rule stays whole.")

    values = "\n".join(
        f"       - {c} = {_commentable(signature[c])}"
        for c in RULE_DISCRIMINANT_FIELDS if c in signature)

    return f"""<!-- Aura-SOC - rule {rule_id} (level {level}). AUTOMATICALLY GENERATED.
     Do not edit by hand: regenerated by `python -m soc_agent.rule_tuning`.
     Naming convention and load-order trap: see rules/README.md
     signature-canonique: {_commentable(_canonical(signature), 400)} -->
<group name="local,soc_ai_auto_tuning,">

  <!-- Exception derived from {n_fp} incidents judged `false_positive` by the AI
       triage (incidents {", ".join(f"#{i}" for i in incidents)}).

       Exonerated signature:
{values}

       {effect}

       ANCHORED conditions (`^...$`, pcre2, escaped value): the exception can
       only cover the exact observed value, never a variant containing it. An
       attacker cannot slip in by prefixing or suffixing the value.

       Deployed only after a `/logtest` replay proving that (a) the FP event does
       fall here and (b) a REAL event of the same parent rule, with another
       value, STILL falls on {parent} at its original level. -->

  <rule id="{rule_id}" level="{level}">
    <if_sid>{escape(parent)}</if_sid>
{chr(10).join(conditions)}
    <description>Auto-tuning Aura-SOC: known false positive of rule {escape(parent)}</description>
  </rule>

</group>
"""


# --- Wazuh API: logtest, restart, status -------------------------------------

def _token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def logtest(tok: str, event: str, location: str) -> tuple[str | None, int | None]:
    """(rule_id, level) returned by the engine for this event, through the API.

    We go through the API and not the `wazuh-logtest` binary: this module runs in
    its own container, with no access to the manager filesystem nor to the Docker
    socket.
    """
    r = requests.put(
        f"{config.WAZUH_API_URL}/logtest",
        headers={"Authorization": f"Bearer {tok}"},
        json={"event": event, "log_format": "syslog",
              "location": location or "soc-ai-rule-tuning"},
        verify=False, timeout=30)
    r.raise_for_status()
    rule = (((r.json().get("data") or {}).get("output") or {}).get("rule") or {})
    level = rule.get("level")
    return rule.get("id"), (int(level) if level is not None else None)


def _restart(tok: str) -> bool:
    """Reloads the ruleset. True when the manager is operational again.

    A rule change is only taken into account when the manager restarts — hence
    the hourly cadence of this job, rather than the per-minute one of the others.
    """
    r = requests.put(f"{config.WAZUH_API_URL}/manager/restart",
                     headers={"Authorization": f"Bearer {tok}"},
                     verify=False, timeout=60)
    r.raise_for_status()
    for _ in range(config.RULE_TUNING_WAIT_ATTEMPTS):
        time.sleep(5)
        try:
            tok = _token()
            s = requests.get(f"{config.WAZUH_API_URL}/manager/status",
                             headers={"Authorization": f"Bearer {tok}"},
                             verify=False, timeout=15)
            items = (s.json().get("data") or {}).get("affected_items") or [{}]
            if items[0].get("wazuh-analysisd") == "running":
                return True
        except requests.RequestException:
            continue
    return False


# --- selecting the candidates ------------------------------------------------

def _event(raw: dict) -> tuple[str, str] | None:
    """Replayable (full_log, location), or None when the alert is not replayable.

    An alert without `full_log` (FIM, rootcheck, modules producing already
    structured JSON) cannot be replayed in logtest — hence not proven, hence
    refused. Better do nothing than deploy without proof.
    """
    log = raw.get("full_log")
    if not log or "\n" in str(log):
        return None
    return str(log), str(raw.get("location") or "")


def _counter_example(conn, parent: str, signature: dict) -> tuple[str, str] | None:
    """A REAL event of the same parent rule, but of another signature.

    It is what proves the exception does not neutralise the rule. Searched among
    the alerts actually ingested: a synthetic counter-example would only prove
    the regex written holds, not that detection holds on this environment's
    traffic.
    """
    lines = conn.execute(
        "SELECT raw FROM alerts WHERE rule_id = %s "
        "ORDER BY ts DESC LIMIT %s",
        (parent, config.RULE_TUNING_COUNTER_EXAMPLE_CANDIDATES)).fetchall()
    for l in lines:
        raw = l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
        # A single different value on a discriminant field is enough: this
        # event is not covered by the exception, it must stay detected.
        if any(str(_value_field(raw, c) or "") != signature[c]
               for c in RULE_DISCRIMINANT_FIELDS if c in signature):
            ev = _event(raw)
            if ev:
                return ev
    return None


def _fp_example(conn, incidents: list[int]) -> tuple[dict, tuple[str, str]] | None:
    """(raw, event) of an alert representative of the FP incidents."""
    # BOUNDED: we look for ONE representative alert, not the collection.
    # Without a limit, a list of flood incidents brought back hundreds of
    # thousands of full `raw` documents to keep a single one (1 GB for 126,508
    # alerts, see whitelist._signature). Most recent first: it is the current
    # state of the FP we want to illustrate.
    lines = conn.execute(
        "SELECT raw FROM alerts WHERE incident_id = ANY(%s) "
        "ORDER BY ts DESC LIMIT 500",
        (incidents,)).fetchall()
    for l in lines:
        raw = l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
        ev = _event(raw)
        if ev:
            return raw, ev
    return None


def _signatures_already_processed(folder: Path) -> set[str]:
    """Canonical signatures already covered by a generated rule.

    The values read back here are those WRITTEN in the comment, hence passed
    through `_commentable`. The comparison in `analyze` applies the same
    transformation: without it, any signature containing `--`, `<` or `>` would
    never recognise itself and its rule would be regenerated on every pass — one
    manager restart per cycle, forever.

    The `signature-canonique:` marker keeps its French name: it is written inside
    every rule file already deployed on the manager, and renaming it would make
    them all unrecognised, hence regenerated.
    """
    seen: set[str] = set()
    for f in folder.glob("*.xml"):
        text = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"signature-canonique: (.+)", text)
        if m:
            seen.add(m.group(1).strip())
    return seen


def _next_id(folder: Path) -> int:
    used = {int(m.group(1))
                for f in folder.glob("*.xml")
                if (m := re.match(r"^(\d+)-", f.name))}
    for rid in range(config.RULE_TUNING_ID_MIN, config.RULE_TUNING_ID_MAX + 1):
        if rid not in used:
            return rid
    raise RuntimeError("range of automatic rule identifiers exhausted")


# --- orchestration -----------------------------------------------------------

def analyze(min_fp: int, simulation: bool) -> list[dict]:
    """Generates, proves and deploys the due rules. Returns the decisions."""
    folder = Path(config.RULE_TUNING_DIR)
    if not folder.is_dir():
        raise RuntimeError(f"{folder} not found — the manager rule directory "
                           "must be mounted into this container")

    level = config.RULE_TUNING_LEVEL
    if level == 0 and not config.RULE_TUNING_ALLOW_LEVEL_0:
        raise RuntimeError(
            "RULE_TUNING_LEVEL=0 (full suppression) requires "
            "RULE_TUNING_ALLOW_LEVEL_0=true")

    decisions: list[dict] = []
    placed: list[tuple[Path, dict]] = []   # (file, verification context)

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_by_sig, sig_tp = _incidents_by_verdict(
            conn, RULE_DISCRIMINANT_FIELDS)
        already = _signatures_already_processed(folder)
        n_existing = len(already)
        tok = _token()

        for canon, e in sorted(fp_by_sig.items()):
            signature, n = e["signature"], len(e["incidents"])

            def refusal(reason):
                decisions.append({"signature": canon, "action": "refused",
                                  "reason": reason})

            # Compared in the form written into the comment (see
            # _signatures_already_processed), not in the raw form.
            if _commentable(canon, 400) in already:
                continue
            if canon in sig_tp:
                refusal("also seen as true_positive"); continue
            if e["max_level"] >= config.WHITELIST_MAX_LEVEL:
                refusal(f"level {e['max_level']} >= {config.WHITELIST_MAX_LEVEL}")
                continue
            if n < min_fp:
                decisions.append({"signature": canon, "action": "pending",
                                  "reason": f"{n}/{min_fp} FP"})
                continue
            if not any(c in signature for c in RULE_DISCRIMINANT_FIELDS):
                refusal("signature too broad: rule_id alone is not enough"); continue
            parent = signature.get("rule_id")
            if not parent:
                refusal("no rule_id: cannot chain through if_sid"); continue
            if n_existing + len(placed) >= config.RULE_TUNING_MAX_RULES:
                refusal(f"cap of {config.RULE_TUNING_MAX_RULES} automatic rules reached")
                continue

            ex = _fp_example(conn, e["incidents"])
            if ex is None:
                refusal("no replayable alert (no full_log)"); continue
            raw_fp, ev_fp = ex

            counter = _counter_example(conn, parent, signature)
            if counter is None:
                refusal("no counter-example in database: non-invalidation of "
                      "the rule cannot be proven"); continue

            # Before loading: both events must fall on the parent. Otherwise
            # the signature does not describe what we think, and the check
            # afterwards would be uninterpretable.
            rid_fp, lvl_fp = logtest(tok, *ev_fp)
            rid_ce, lvl_ce = logtest(tok, *counter)
            if rid_fp != parent:
                refusal(f"FP replay falls on {rid_fp}, not on {parent}"); continue
            if rid_ce != parent:
                refusal(f"counter-example replay falls on {rid_ce}, not on {parent}")
                continue

            # The batch files are only written at the end of the loop: so we
            # offset by len(placed) not to reassign the same id.
            rid = _next_id(folder) + len(placed)
            xml = build_xml(rid, parent, level, signature, raw_fp, n,
                                 e["incidents"])
            if xml is None:
                refusal("signature not translatable into rule conditions"); continue

            path = folder / f"{rid}-auto-{_slug(canon)}.xml"
            if simulation:
                decisions.append({"signature": canon, "action": "simulated",
                                  "file": path.name, "xml": xml, "fp": n})
                continue

            path.write_text(xml, encoding="utf-8")
            placed.append((path, {
                "canon": canon, "parent": parent, "fp": n,
                "ev_fp": ev_fp, "counter": counter,
                "original_level": lvl_ce, "file": path.name}))

        if not placed:
            return decisions

        # A single restart for the whole batch: that is the expensive part.
        if not _restart(tok):
            for path, ctx in placed:
                path.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "rolled_back",
                                  "reason": "the manager did not come back "
                                            "operational — rules removed"})
            _restart(_token())
            return decisions

        tok = _token()
        to_remove = []
        for path, ctx in placed:
            rid_fp, lvl_fp = logtest(tok, *ctx["ev_fp"])
            rid_ce, lvl_ce = logtest(tok, *ctx["counter"])
            expected = path.name.split("-", 1)[0]

            if rid_fp != expected or lvl_fp != level:
                to_remove.append((path, ctx,
                                  f"the FP event falls on {rid_fp} (level "
                                  f"{lvl_fp}), expected {expected} level {level}"))
            elif rid_ce != ctx["parent"] or lvl_ce != ctx["original_level"]:
                # THE guardrail: the exception bit on something other than itself.
                to_remove.append((path, ctx,
                                  "RULE INVALIDATED: the counter-example falls "
                                  f"on {rid_ce} level {lvl_ce} instead of "
                                  f"{ctx['parent']} level {ctx['original_level']}"))
            else:
                decisions.append({"signature": ctx["canon"], "action": "created",
                                  "file": ctx["file"], "fp": ctx["fp"],
                                  "level": level, "parent": ctx["parent"]})
                conn.execute(
                    "UPDATE incidents SET status = 'whitelisted' "
                    "WHERE id = ANY(%s)",
                    ([i for i in fp_by_sig[ctx["canon"]]["incidents"]],))
                conn.commit()

        if to_remove:
            for path, ctx, reason in to_remove:
                path.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "rolled_back",
                                  "reason": reason})
            _restart(_token())

    return decisions


def generated_rules() -> list[dict]:
    """The auto-generated rules present on disk.

    The directory IS the state (no table): so we read the files back rather than
    a database that could lie about what the manager actually loads.
    """
    folder = Path(config.RULE_TUNING_DIR)
    files = sorted(folder.glob("*-auto-*.xml")) if folder.is_dir() else []
    rules = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        rid = re.search(r'<rule id="(\d+)" level="(\d+)"', text)
        parent = re.search(r"<if_sid>([^<]+)</if_sid>", text)
        canon = re.search(r"signature-canonique: (.+)", text)
        rules.append({
            "file": f.name,
            "rule_id": rid.group(1) if rid else None,
            "level": int(rid.group(2)) if rid else None,
            "parent": parent.group(1) if parent else None,
            "signature": canon.group(1).strip() if canon else None,
        })
    return rules


def list_rules() -> None:
    rules = generated_rules()
    if not rules:
        print("No automatically generated rule.")
        return
    for r in rules:
        print(f"  {r['file']}")
        print(f"      parent {r['parent'] or '?'} -> level "
              f"{r['level'] if r['level'] is not None else '?'}   "
              f"{r['signature'] or ''}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="shows the XML that would be deployed, touches nothing")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.list:
        list_rules()
        return

    for d in analyze(args.min_fp, args.simulation):
        if d["action"] == "created":
            print(f"  CREATED    {d['file']}  (parent {d['parent']}, "
                  f"level {d['level']}, {d['fp']} FP)")
        elif d["action"] == "simulated":
            print(f"  SIMULATED  {d['file']}  ({d['fp']} FP)\n{d['xml']}")
        elif d["action"] == "rolled_back":
            print(f"  ROLLED BACK {d['signature']} — {d['reason']}")
        elif d["action"] == "refused":
            print(f"  refused    {d['signature']} — {d['reason']}")
        else:
            print(f"  pending    {d['signature']} — {d['reason']}")


if __name__ == "__main__":
    main()
