"""Reversible pseudonymisation before sending to the cloud LLM (DeepSeek).

SOC data leaves the host: we must protect the CLIENT's confidentiality without
destroying the triage signal. The underlying finding (visible in render.py):
**what decides the verdict is the attributes, not the identifiers.** An IP rated
98/100, RU, 2100 reports, a `.lockbit` extension, a `/root` path, a successful
auth — none of those signals needs the literal value of the IP, the hostname or
the account.

Principle: separate the IDENTIFIER (PII / client asset, never leaves) from the
ATTRIBUTE (the analytic signal, non-identifying -> leaves verbatim).

- Internal assets (hostname, named accounts, private IPs, paths) -> stable token
  `<HOTE_1>`, `<COMPTE_1>`, `<IP_1>`, `<FICHIER_1>`, consistent within the
  incident to preserve the model's chains of reasoning.
- External IOCs (attacker public IP, malware hash) -> kept in clear: this is not
  client PII, it is threat intel already known to VT / AbuseIPDB. A deliberate
  product choice.
- Attributes (score, country, positives, extension, path category) -> kept.

The token prefixes stay French (`HOTE`, `COMPTE`, `FICHIER`, `OBJET`, `DIVERS`):
they are read by the model, whose prompts are French, and they are PERSISTED in
`anonymization_map` — renaming them would break the rehydration of every map
already stored.

The token->value mapping stays in loopback Postgres (same data as `alerts.raw`,
same locality — zero new exposure) and serves to rehydrate the LLM's answer: the
analyst sees the real values in IRIS, only DeepSeek saw the tokens.

This module strongly reduces identifiability; it does not remove it. Fail-closed
guardrail: `check_leak` refuses the send if a known internal identifier, an
e-mail or a private IP survives in the final text.
"""

import copy
import ipaddress
import re

# Generic accounts: roles, not people. We KEEP them — "root" or
# "administrator" carries the privilege signal and identifies nobody.
GENERIC_ACCOUNTS = {"root", "administrator", "admin", "system", "guest",
                      "-", "n/a", "none", "localsystem", "networkservice"}

# UEBA traits whose value is an ATTRIBUTE and not an identifier: it carries the
# analytic signal ("unusual country", "unusual port") without naming a client
# asset, so it leaves verbatim. Any trait absent from this list is
# pseudonymised — including a trait added later in ueba.py (see the default
# branch in `anonymize`).
UEBA_TRAIT_ATTRIBUTES = {"pays", "heure", "dst_port", "rule_id", "chaine_mitre"}

_HASH = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Paths inside free text. Unix: at least two segments ("/a/b") so it is not
# confused with "15/15". The `<FICHIER_1>` tokens do not match ("<" is outside
# the class), so a residual path is a real leak.
_UNIXPATH = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]+")
_WINPATH = re.compile(r"[A-Za-z]:\\[\w.\-\\]+")
# Extension up to 12 characters: covers ransomware extensions (.lockbit,
# .encrypted, .cryptolocker), which carry a strong signal.
_EXT = re.compile(r"(\.[A-Za-z0-9]{1,12})$")
_TOKEN = re.compile(r"<([A-Z]+)_(\d+)>")


def _is_internal(ip: str) -> bool:
    """Private / loopback / link-local / reserved / CGNAT IP -> internal asset."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Anonymizer:
    """Assigns stable, reversible tokens.

    Seeded with an existing mapping (token->value), it reuses the same tokens: a
    re-triaged incident produces exactly the same pseudonyms, which is what makes
    passes comparable.
    """

    def __init__(self, existing_map: dict | None = None):
        self._t2v: dict[str, str] = dict(existing_map or {})
        self._v2t: dict[str, str] = {v: t for t, v in self._t2v.items()}
        self._counters: dict[str, int] = {}
        for t in self._t2v:
            m = _TOKEN.match(t)
            if m:
                p, n = m.group(1), int(m.group(2))
                self._counters[p] = max(self._counters.get(p, 0), n)

    def token(self, value: str, prefix: str) -> str:
        value = str(value)
        if value in self._v2t:
            return self._v2t[value]
        n = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = n
        t = f"<{prefix}_{n}>"
        self._t2v[t] = value
        self._v2t[value] = t
        return t

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._t2v)

    # --- transformations par type ------------------------------------------

    def ip(self, value: str) -> str:
        """Internal IP -> token; public IP (attacker IOC) -> clear.

        A value that is NOT an IP is masked, not let through: `_is_internal`
        returns False on an unparsable string, which used to send it out in
        clear. An IP field containing something else is unexpected data — we do
        not know what it carries, so we treat it as sensitive. Fail-closed, like
        the rest of the module.
        """
        v = str(value)
        try:
            public = ipaddress.ip_address(v).is_global
        except ValueError:
            return self.token(v, "DIVERS")
        return v if public else self.token(v, "IP")

    def account(self, value: str) -> str:
        if str(value).strip().lower() in GENERIC_ACCOUNTS:
            return value
        return self.token(value, "COMPTE")

    def object(self, value: str) -> str:
        """File / process / hash at stake (the `entity` field)."""
        v = str(value)
        if _HASH.match(v):
            return v  # malware hash = external IOC, kept in clear
        if "/" in v or "\\" in v:
            return self.path(v)
        return self.token(v, "OBJET")

    def path(self, p: str) -> str:
        """Keeps the category (1st segment) and the extension, tokenises the middle.

        `/home/jdupont/rapport.xlsx` -> `/home/<FICHIER_1>.xlsx`. The category
        (`/home`) and the extension (`.xlsx`) are not identifying and carry
        signal; the middle (`jdupont/rapport`, which holds the account and the
        file name) is masked. The token maps to that middle alone, so
        rehydration rebuilds the exact path.
        """
        segs = [s for s in re.split(r"[\\/]", p) if s]
        if not segs:
            return self.token(p, "FICHIER")
        drive = re.match(r"^[A-Za-z]:$", segs[0])
        cat = segs[0]
        remains = "/".join(segs[1:]) if not drive else "\\".join(segs[1:])
        if not remains:  # single-segment path (e.g. "procès.exe")
            m = _EXT.search(cat)
            ext = m.group(1) if m else ""
            middle = cat[: -len(ext)] if ext else cat
            return f"{self.token(middle, 'FICHIER')}{ext}"
        m = _EXT.search(remains)
        ext = m.group(1) if m else ""
        middle = remains[: -len(ext)] if ext else remains
        tok = self.token(middle, "FICHIER")
        if drive:
            return f"{cat}\\{tok}{ext}"
        prefix = "/" if p.startswith("/") else ""
        return f"{prefix}{cat}/{tok}{ext}"

    def free_text(self, text: str, forbidden: list[str]) -> str:
        """Cleans a free field (rule_desc): replaces the already-known internal
        values by their token, then residual e-mails and private IPs.

        PATHS are handled first, whole (through `path`): a path such as
        `/home/elie/note.txt` carries an account and a file name which, taken
        alone, would not be in `forbidden`. Handling them first avoids leaking
        those identifiers buried in a `rule_desc`.
        """
        out = text
        out = _WINPATH.sub(lambda m: self.path(m.group(0)), out)
        out = _UNIXPATH.sub(lambda m: self.path(m.group(0)), out)
        # Then the known identifiers, longest first (avoids partial
        # replacements). Only tokens whose value is the whole string (host,
        # account, IP): never the file tokens, whose value is a middle of path —
        # that would break rehydration.
        for v in sorted(forbidden, key=len, reverse=True):
            if v and v in out:
                out = out.replace(v, self._v2t.get(v, self.token(v, "DIVERS")))
        out = _EMAIL.sub(lambda m: self.token(m.group(0), "EMAIL"), out)
        out = _IPV4.sub(
            lambda m: self.token(m.group(0), "IP") if _is_internal(m.group(0))
            else m.group(0), out)
        return out


def _raw_dict(raw) -> dict:
    import json
    return raw if isinstance(raw, dict) else json.loads(raw)


def anonymize(anon: Anonymizer, incident: dict,
               alerts: list[dict]) -> tuple[dict, list[dict], list[str]]:
    """Pseudonymised copies of (incident, alerts) plus the forbidden values.

    Touches ONLY the fields render.py consumes. The originals (in database) are
    not modified: pseudonymisation lives only on the path to the LLM.
    """
    inc = copy.deepcopy(incident)
    forbidden: set[str] = set()

    if inc.get("agent_name"):
        forbidden.add(str(inc["agent_name"]))
        inc["agent_name"] = anon.token(inc["agent_name"], "HOTE")

    alerts2 = []
    for a in alerts:
        b = copy.deepcopy(a)

        if b.get("srcip"):
            if _is_internal(str(b["srcip"])):
                forbidden.add(str(b["srcip"]))
            b["srcip"] = anon.ip(str(b["srcip"]))

        if b.get("srcuser") and str(b["srcuser"]).strip().lower() \
                not in GENERIC_ACCOUNTS:
            forbidden.add(str(b["srcuser"]))
            b["srcuser"] = anon.account(str(b["srcuser"]))

        if b.get("entity"):
            b["entity"] = anon.object(str(b["entity"]))

        # raw: only the identifier fields read by _enrichment.
        raw = _raw_dict(b.get("raw") or {})
        data = raw.get("data", {})
        abuse = data.get("abuseipdb")
        if isinstance(abuse, dict) and abuse.get("srcip"):
            if _is_internal(str(abuse["srcip"])):
                forbidden.add(str(abuse["srcip"]))
            abuse["srcip"] = anon.ip(str(abuse["srcip"]))
        vt = data.get("virustotal")
        if isinstance(vt, dict) and isinstance(vt.get("source"), dict):
            f = vt["source"].get("file")
            if f:
                forbidden.add(str(f))
                vt["source"]["file"] = anon.object(str(f))
        geo = raw.get("GeoLocation")
        if isinstance(geo, dict):
            geo.pop("city_name", None)  # city: too fine-grained, dropped
        b["raw"] = raw

        alerts2.append(b)

    # UEBA patterns: they carry RAW VALUES pulled from the logs (binary path,
    # account, IP), hence PII and client assets. Without this pass, `check_leak`
    # would refuse the incident — fail-closed — and EVERYTHING the behavioural
    # engine reports would be silently dropped from triage. We pseudonymise by
    # TYPE, with the same method as the matching field: a path keeps its category
    # and extension, a public IP stays in clear (IOC), and so does a generic
    # account.
    patterns = inc.get("ueba_patterns")
    if isinstance(patterns, list):
        clean = []
        for m in patterns:
            m = dict(m)
            v = m.get("value")
            if v:
                v = str(v)
                trait = m.get("trait")
                if trait == "compte":
                    if v.strip().lower() not in GENERIC_ACCOUNTS:
                        forbidden.add(v)
                    m["value"] = anon.account(v)
                elif trait == "srcip":
                    if _is_internal(v):
                        forbidden.add(v)
                    m["value"] = anon.ip(v)
                elif trait not in UEBA_TRAIT_ATTRIBUTES:
                    # Everything else goes through `object` — including a trait
                    # this module does not know yet. An EXCLUSION list and not an
                    # inclusion list, deliberately: with an inclusion list,
                    # adding a trait in ueba.py without thinking of this file
                    # lets it leak in clear. That is not theoretical — the
                    # `file` trait was added later, and `check_leak` refused the
                    # incident (fail-closed), which would have silently starved
                    # everything the engine reports of triage.
                    m["value"] = anon.object(v)
            clean.append(m)
        inc["ueba_patterns"] = clean

    # Free-text pass over rule_desc, with the identifiers collected.
    forbidden_list = sorted(forbidden)
    # The notes ("inédit ici, vu sur 2 autres hôtes") are generated by us, but
    # nothing in them forbids an identifier copied from a log: we run them
    # through the same filter as the rule descriptions.
    for m in (inc.get("ueba_patterns") or []):
        if m.get("note"):
            m["note"] = anon.free_text(str(m["note"]), forbidden_list)
    for b in alerts2:
        if b.get("rule_desc"):
            b["rule_desc"] = anon.free_text(str(b["rule_desc"]),
                                              forbidden_list)

    return inc, alerts2, forbidden_list


def rehydrate(text: str | None, mapping: dict[str, str]) -> str | None:
    """Replaces tokens by the real values (for the analyst view).

    Longest token first: `<FICHIER_11>` before `<FICHIER_1>` (even though the
    trailing `>` already stops one being a prefix of the other).

    Bracket-less fallback: asked to put a token in **bold**, the model sometimes
    writes `**HOTE_1**` instead of `**<HOTE_1>**` — it treats `<...>` as markup
    to clean rather than an opaque token (case #197, regression of 2026-08-09
    after the formatting instruction was added). An exact replacement of the
    whole token then left the bare form intact, never rehydrated. The bare name
    (`HOTE_1`, `IP_3`...) is a token forged by this module (fixed prefix plus
    counter): too specific to match a word of the text by accident, hence safe
    as a fallback.
    """
    if not text:
        return text
    for token in sorted(mapping, key=len, reverse=True):
        text = text.replace(token, mapping[token])
    for token in sorted(mapping, key=len, reverse=True):
        if token.startswith("<") and token.endswith(">"):
            text = text.replace(token[1:-1], mapping[token])
    return text


class LeakError(RuntimeError):
    """An internal identifier survived pseudonymisation."""


def check_leak(text: str, forbidden: list[str]) -> None:
    """Fail-closed guardrail before the cloud send.

    Raises if a known internal value, an e-mail or a private IP survives. Public
    IPs are tolerated (external IOC kept in clear, by design).
    """
    presents = [v for v in forbidden if v and v in text]
    if presents:
        raise LeakError(
            f"internal identifier(s) not pseudonymised: {presents}")
    if _EMAIL.search(text):
        raise LeakError("residual e-mail in the text sent to the cloud")
    for m in _IPV4.findall(text):
        if _is_internal(m):
            raise LeakError(f"residual private IP: {m}")
    # A residual file path: the `<FICHIER_n>` tokens do not match ("<" outside
    # the class), so any match is a real, non-pseudonymised path.
    for regex in (_UNIXPATH, _WINPATH):
        m = regex.search(text)
        if m:
            raise LeakError(f"residual non-pseudonymised path: {m.group(0)}")
