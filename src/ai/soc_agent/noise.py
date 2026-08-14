"""Noise filtering, on two levels (see noise_filter.yaml).

A clean split between the two stages:

- `clauses_must_not()` produces the filters pushed into the query to the
  indexer. Those alerts are never ingested. We drop them as early as possible,
  where it is cheapest.
- `deletion_reason()` judges an alert we already fetched. It will be ingested
  and kept for audit, but marked and excluded from correlation.

The same criterion (an IP, an account, a rule) can belong to either stage
depending on its `query_level`, decided in the YAML. Here we only apply it; the
policy lives in the config file.
"""

from __future__ import annotations

from pathlib import Path

import yaml

CONFIG_DEFAULT = Path(__file__).parent / "noise_filter.yaml"

# Wazuh field targeted by each simple entry type. Used on both sides: to build
# the must_not (OpenSearch path) and to read the value out of the raw document
# (same path, dotted notation).
FIELD = {
    "rule_id": "rule.id",
    "src_user": "data.srcuser",
    "dst_user": "data.dstuser",
    "command": "data.command",
    # Discriminant of web rules. Reserved for rule_tuning.py: in the rule
    # engine `<url>` is a native option, whereas a post-retrieval filter on the
    # URL would be pointless (the alert is already produced and indexed).
    "url": "data.url",
    "agent_name": "agent.name",
    "agent_id": "agent.id",
}

# The file at stake has no single location: depending on the decoder it is
# syscheck.path, the VirusTotal file, the auditd target... so "file" is a
# VIRTUAL field, resolved by trying each in turn. Reserved for composites
# (post-retrieval): it lets us whitelist one precise path without blinding a
# whole rule — e.g. /tmp/eicar.com without neutralising the VirusTotal rule.
FILE_PATHS = [
    "syscheck.path",
    "data.virustotal.source.file",
    "data.audit.exe",
    "data.audit.file.name",
    "data.win.eventdata.image",
]

# Fields allowed in a composite match_all (simple ones plus the virtual one).
FIELD_COMPOSITE = set(FIELD) | {"file"}


def _read(src: dict, path: str):
    """Value of a Wazuh field in dotted notation inside the raw document."""
    node = src
    for key in path.split("."):
        if not isinstance(node, dict):
            return None
        node = node.get(key)
        if node is None:
            return None
    return node


def _value_field(src: dict, field: str):
    """Value of a composite field, including the virtual "file" one."""
    if field == "file":
        for path in FILE_PATHS:
            v = _read(src, path)
            if v:
                return v
        return None
    return _read(src, FIELD.get(field, field))


class NoiseFilter:
    """Filtering rules loaded from the YAML.

    Each simple entry becomes a (type, value, reason) triple, filed according to
    its query_level. Composites are always post-retrieval.
    """

    def __init__(self, config: dict):
        self.query_level: list[tuple[str, str, str]] = []
        self.post: list[tuple[str, str, str]] = []
        self.composites: list[dict] = []
        self._load(config.get("filters", {}))

    def _add(self, field_type: str, value, query_level: bool, reason: str):
        target = self.query_level if query_level else self.post
        target.append((field_type, str(value), reason or field_type))

    def add_composite(self, match_all: dict, name: str) -> None:
        """Adds a composite rule (used for the exceptions stored in database).

        Always post-retrieval: a broad exception must stay recoverable, so it is
        never dropped on the indexer side.
        """
        self.composites.append({"name": name, "match_all": match_all})

    def _load(self, f: dict) -> None:
        for e in f.get("rules", {}).get("ignore_rule_ids") or []:
            self._add("rule_id", e["id"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("actors", {}).get("ignore_src_users") or []:
            self._add("src_user", e["user"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("destinations", {}).get("ignore_dst_users") or []:
            self._add("dst_user", e["user"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("commands", {}).get("ignore_commands") or []:
            self._add("command", e["command"], e.get("query_level", False),
                          e.get("reason", ""))
        hosts = f.get("hosts", {})
        for e in hosts.get("ignore_agent_names") or []:
            self._add("agent_name", e["name"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in hosts.get("ignore_agent_ids") or []:
            self._add("agent_id", e["id"], e.get("query_level", False),
                          e.get("reason", ""))
        for c in f.get("composite") or []:
            if c.get("match_all"):
                self.composites.append(c)

    def clauses_must_not(self) -> list[dict]:
        """OpenSearch clauses for the query_level: true entries."""
        return [{"term": {FIELD[field_type]: value}}
                for field_type, value, _ in self.query_level
                if field_type in FIELD]

    def deletion_reason(self, src: dict) -> str | None:
        """Post-retrieval deletion reason, or None.

        An alert matched at query_level should not reach here (the must_not
        dropped it), but we re-check anyway: if the filter was added afterwards,
        the older alert already in database must be suppressible on replay.
        """
        for field_type, value, reason in self.post + self.query_level:
            path = FIELD.get(field_type)
            if path and str(_read(src, path)) == value:
                return reason

        for c in self.composites:
            conditions = c["match_all"]
            # Every key must be known AND match. Without the first test, a
            # composite with unknown keys would give an empty all(), hence
            # true, and would suppress every alert.
            if conditions and all(k in FIELD_COMPOSITE for k in conditions) and all(
                    str(_value_field(src, k)) == str(v)
                    for k, v in conditions.items()):
                return c.get("name") or c.get("description") or "composite"
        return None


def load_with_db(conn, path: str | None = None) -> NoiseFilter:
    """Full filter: noise_filter.yaml (human) + whitelist_rules (automatic).

    Rebuilt on every call, with no cache: the automatic exceptions change on
    every cycle. Call it once per run and pass it down, not once per alert.
    """
    p = Path(path) if path else CONFIG_DEFAULT
    with open(p, encoding="utf-8") as fh:
        noise_filter = NoiseFilter(yaml.safe_load(fh) or {})

    # Explicit tuple cursor: if the calling connection uses dict_row,
    # unpacking "for sig, match_all, reason in ..." would iterate each row's
    # KEYS rather than its values, and load broken composites.
    from psycopg.rows import tuple_row
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT signature, match_all, reason FROM whitelist_rules "
                    "WHERE active")
        for sig, match_all, reason in cur.fetchall():
            noise_filter.add_composite(match_all, reason or sig)
    return noise_filter
