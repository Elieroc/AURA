"""Filtre VirusTotal des exécutables légitimes, AVANT corrélation.

But : un exécutable propre (Sysmon, FIM, intégration VT) ne doit ni peser dans un
case, ni en ouvrir un s'il est le seul événement. On confronte le HASH du binaire
à la réputation VirusTotal ; si VT le connaît et qu'aucun moteur ne le juge
malveillant, l'alerte qui le porte est marquée `suppressed` — donc exclue de la
corrélation (`correlate` filtre `NOT suppressed`), exactement comme le noise filter.

Choix de conception :

- **Déterministe, pas le LLM.** La réputation VT est une donnée dure ; la décision
  de ne pas ouvrir de case sur un binaire propre ne passe pas par le modèle.
- **Portée volontairement étroite.** On ne filtre QUE des exécutables déposés hors
  des répertoires système. Un binaire signé de System32 (`powershell.exe`,
  `certutil.exe`…) est « clean » pour VT mais peut être détourné (LOLBin) : là, la
  détection est comportementale, pas sur le fichier — on n'y touche pas.
- **Dans le doute, on garde.** Un hash inconnu de VT (404) ou vu de trop peu de
  moteurs n'est PAS légitime : verdict `unknown`, aucune suppression.
- **Cache obligatoire.** L'API publique est plafonnée (4 req/min, 500/jour) : les
  verdicts sont mis en cache (`vt_file_reputation`, TTL `VT_CACHE_TTL_DAYS`) et le
  nombre d'appels réseau par passage est borné (`VT_MAX_LOOKUPS`). Le reste est
  retenté au cycle suivant.
- **Auditable et réversible.** `suppress_reason` porte les stats VT ; un re-ingest
  réévalue. Un hash qui deviendrait malveillant plus tard n'est plus filtré.
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


def _chemin(data: dict, raw: dict) -> str:
    """Chemin de l'exécutable concerné (pour la portée « déposé hors système »)."""
    win = (data.get("win") or {}).get("eventdata") or {}
    audit = data.get("audit") or {}
    sc = raw.get("syscheck") or {}
    return str(win.get("image") or audit.get("exe")
              or (audit.get("file") or {}).get("name")
              or sc.get("path") or raw.get("entity") or "")


def _hash(data: dict, raw: dict) -> str | None:
    """Hash de fichier de l'alerte, en minuscules. sha256 > sha1 > md5.

    Sources : Sysmon `data.win.eventdata.hashes`, FIM `syscheck.*_after`,
    intégration VT `data.virustotal.source.*`.
    """
    trouves: dict[str, str] = {}

    win = (data.get("win") or {}).get("eventdata") or {}
    for algo, val in _RE_HASH_KV.findall(str(win.get("hashes") or "")):
        trouves[algo.lower()] = val.lower()

    sc = raw.get("syscheck") or {}
    for algo in ("sha256", "sha1", "md5"):
        v = sc.get(f"{algo}_after") or sc.get(algo)
        if v:
            trouves.setdefault(algo, str(v).lower())

    vt = (data.get("virustotal") or {}).get("source") or {}
    for algo in ("sha256", "sha1", "md5"):
        if vt.get(algo):
            trouves.setdefault(algo, str(vt[algo]).lower())

    for algo, rx in (("sha256", _RE_SHA256), ("sha1", _RE_SHA1), ("md5", _RE_MD5)):
        h = trouves.get(algo)
        if h and rx.match(h):
            return h
    return None


def _hors_systeme(chemin: str) -> bool:
    """Vrai si l'exécutable N'EST PAS dans un répertoire système (donc filtrable)."""
    # L'eventchannel Windows double les backslashes (C:\\\\Windows\\\\...):
    # les replier vers un seul, sinon le prefixe systeme ne matche jamais
    # et un LOLBin propre de System32 (net1.exe...) est suppresse a tort.
    p = chemin.lower().replace("\\\\", "\\")
    if not p:
        return False
    return not p.startswith(config.VT_DIRS_SYSTEME)


def _verdict(stats: dict, total: int) -> str:
    mal = stats.get("malicious", 0)
    sus = stats.get("suspicious", 0)
    if mal > 0 or sus > 0:
        return "malicious"
    if total >= config.VT_MIN_ENGINES:
        return "legit"
    return "unknown"


def _lire_cache(conn, h: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM vt_file_reputation WHERE sha256 = %s", (h,)).fetchone()
    if not row:
        return None
    age = datetime.now(timezone.utc) - row["checked_at"]
    if age > timedelta(days=config.VT_CACHE_TTL_DAYS):
        return None          # périmé : on rappellera VT
    return row


def _interroger_vt(h: str) -> dict | None:
    """Appel réseau VT. None si on doit réessayer plus tard (429/erreur réseau)."""
    try:
        r = requests.get(
            f"{config.VT_URL}/files/{h}",
            headers={"x-apikey": config.VT_API_KEY}, timeout=20)
    except requests.RequestException as e:
        log.warning("VT injoignable pour %s : %s", h[:12], e)
        return None
    if r.status_code == 404:
        return {"malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0,
                "total": 0, "verdict": "unknown", "permalink": None}
    if r.status_code == 429:
        log.info("VT quota atteint (429) — on s'arrête pour ce passage")
        return None
    if r.status_code != 200:
        log.warning("VT %s pour %s", r.status_code, h[:12])
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


def _ecrire_cache(conn, h: str, rep: dict) -> None:
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


def filtrer(conn: psycopg.Connection | None = None) -> int:
    """Marque `suppressed` les alertes portant un exécutable jugé légitime par VT.

    Retourne le nombre d'alertes suppressées. Sans clé VT, ne fait rien.
    """
    if not config.VT_API_KEY:
        return 0
    if conn is None:
        with psycopg.connect(config.PG_DSN, row_factory=dict_row) as c:
            return filtrer(c)

    # Candidates : non corrélées, non suppressées, niveau significatif.
    lignes = conn.execute(
        """SELECT id, rule_level, raw FROM alerts
            WHERE incident_id IS NULL AND NOT suppressed AND rule_level >= %s
            ORDER BY ts DESC""",
        (config.VT_EXE_MIN_LEVEL,)).fetchall()

    # hash -> [ids d'alertes], en ne gardant que les exécutables hors système.
    par_hash: dict[str, list[str]] = {}
    for r in lignes:
        raw = r["raw"]
        data = raw.get("data") or {}
        h = _hash(data, raw)
        if not h:
            continue
        if not _hors_systeme(_chemin(data, raw)):
            continue
        par_hash.setdefault(h, []).append(r["id"])
    if not par_hash:
        return 0

    appels = 0
    suppressed = 0
    for h, ids in par_hash.items():
        rep = _lire_cache(conn, h)
        if rep is None:
            if appels >= config.VT_MAX_LOOKUPS:
                continue                 # plafond réseau atteint, au prochain cycle
            if appels:
                # Rendre la transaction AVANT de dormir. `_lire_cache` en a
                # ouvert une, et psycopg ne la referme pas tout seul : sans ce
                # commit, la session reste « idle in transaction » pendant toute
                # la pause. Avec VT_MAX_LOOKUPS appels, cela fait des dizaines
                # de minutes de verrous tenus pour rien — le 2026-08-11, deux
                # sessions du cycle bloquées 19 min ont mis l'ingestion à
                # l'arrêt et fait échouer un ALTER TABLE de migration.
                conn.commit()
                time.sleep(16)           # API publique : 4 req/min
            rep = _interroger_vt(h)
            appels += 1
            if rep is None:
                break                    # 429 / réseau : on arrête proprement
            _ecrire_cache(conn, h, rep)
            conn.commit()

        if rep["verdict"] != "legit":
            continue
        raison = (f"vt_legit_exe: 0/{rep['total']} moteurs positifs "
                  f"(harmless={rep['harmless']}) {rep.get('permalink') or ''}").strip()
        n = conn.execute(
            """UPDATE alerts SET suppressed = true, suppress_reason = %s
                WHERE id = ANY(%s) AND NOT suppressed AND incident_id IS NULL""",
            (raison, ids)).rowcount
        conn.commit()
        if n:
            suppressed += n
            log.info("VT : %d alerte(s) suppressée(s), exe légitime %s (0/%d)",
                     n, h[:12], rep["total"])
    if suppressed:
        log.info("VT : %d alerte(s) écartée(s) (exécutables légitimes), "
                 "%d appel(s) réseau", suppressed, appels)
    return suppressed


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"{filtrer()} alerte(s) suppressée(s)")
