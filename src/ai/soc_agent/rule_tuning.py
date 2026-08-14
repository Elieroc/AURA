"""Réglage automatique des règles Wazuh à partir des faux positifs récurrents.

Deuxième étage de la boucle fermée, complémentaire de `whitelist.py` — pas un
remplaçant :

- `whitelist.py` écrit dans `whitelist_rules`, lu par `noise.py`. L'alerte est
  produite par le manager, indexée, puis écartée par le soc-agent. Le bruit est
  filtré TARD : il a déjà coûté une évaluation de règle, une écriture disque,
  une indexation.
- ce module écarte le bruit AU PLUS TÔT, dans le moteur de règles lui-même : la
  règle fille générée porte un niveau bas (ou 0), donc plus d'alerte de niveau
  utile, plus d'indexation, plus de corrélation. C'est ce que demande la charge
  de la plateforme.

Il sait faire les deux choses :

- **abaisser la sévérité** (défaut, `RULE_TUNING_NIVEAU`) : l'alerte existe
  toujours, elle passe simplement sous le seuil d'ouverture d'incident. On garde
  la trace, on perd le bruit. C'est le mode sûr, et celui qui répond à « ne pas
  invalider la règle » ;
- **supprimer** (niveau 0) : plus aucune alerte. Réservé, verrouillé derrière
  `RULE_TUNING_AUTORISE_NIVEAU_0`.

Les règles générées vivent dans `RULE_TUNING_DIR`, un fichier par règle, mêmes
conventions que les règles écrites à la main (cf. rules/README.md). Le
répertoire est aussi l'ÉTAT : une signature déjà traitée a son fichier, on ne la
retraite pas. Pas de table supplémentaire à migrer, et ce que voit le manager
est exactement ce qui fait foi.

    python -m soc_agent.rule_tuning                # analyse, applique, vérifie
    python -m soc_agent.rule_tuning --simulation   # montre le XML, ne touche à rien
    python -m soc_agent.rule_tuning --lister       # règles générées

## Pourquoi la preuve est empirique et non « par construction »

Traduire une signature en conditions XML demande de deviner le nom du champ tel
que le moteur de règles le voit (`<user>` pour srcuser, `<field name="audit.exe">`
pour un chemin auditd, `<field name="file">` pour du FIM…). Cette table de
correspondance est fragile et dépend du décodeur.

On ne parie donc pas dessus. Chaque règle générée est PROUVÉE par rejeu réel via
l'API `/logtest` du manager, avant et après chargement :

1. avant : l'évènement FP tombe bien sur la règle parente, au niveau attendu ;
2. avant : un CONTRE-EXEMPLE — un évènement de la MÊME règle parente avec une
   valeur DIFFÉRENTE sur le champ discriminant — tombe lui aussi sur la parente ;
3. après chargement : l'évènement FP tombe sur la règle générée, au niveau visé ;
4. après chargement : le contre-exemple tombe TOUJOURS sur la parente, au niveau
   d'origine.

L'étape 4 est le cœur du garde-fou « la whitelist ne doit pas invalider la
règle » : elle vérifie sur du trafic réel que la détection d'origine fonctionne
encore pour tout ce qui n'est pas la signature exonérée. Si un seul contrôle
échoue, le fichier est retiré et le manager rechargé — on revient à l'état
d'avant. Un mauvais nom de champ ne peut donc pas produire une exception muette :
il produit un refus.

Sans contre-exemple disponible en base, on REFUSE : une exception qu'on ne peut
pas prouver inoffensive n'est pas déployée.

## Garde-fous (les mêmes que la whitelist, plus deux)

- signature PRÉCISE : `rule_id` seul est refusé, il faut au moins un champ
  discriminant (compte, commande, fichier, URL) ;
- jamais au-dessus de `WHITELIST_MAX_LEVEL` ;
- jamais une signature vue au moins une fois en `true_positive` ;
- conditions ANCRÉES (`^valeur$`, pcre2, valeur échappée) : une exception sur
  `/tmp/build.sh` ne peut pas couvrir `/tmp/build.sh.evil` ;
- nombre de règles générées plafonné (`RULE_TUNING_MAX_REGLES`).
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

requests.packages.urllib3.disable_warnings()  # certificats auto-signés en local


# Correspondance champ de signature -> option de règle Wazuh. Point de départ
# seulement : ce qui tranche, c'est le rejeu logtest (cf. docstring).
#
# `srcuser` n'a PAS de forme `<field name="srcuser">` : c'est un champ statique
# du moteur, il lève « Field 'srcuser' is static » au chargement. Son option
# dédiée est `<user>`.
_OPTION_STATIC = {
    "src_user": "user",
    "dst_user": "user",
    "url": "url",
}

# Discriminants acceptés ici, un de plus que la whitelist post-retrieval :
# `url`. C'est LE champ des faux positifs web, et de loin le plus gros
# contributeur de charge sur cette plateforme (un reverse proxy exposé sur
# internet). Le filtre post-retrieval ne peut rien en faire d'utile — l'alerte
# est déjà produite et indexée quand il s'exécute ; une règle fille, si.
RULE_DISCRIMINANT_FIELDS = DISCRIMINANT_FIELDS + ("url",)
# Chemin JSON (data.X) -> nom de champ dynamique tel qu'écrit dans une règle.
# Wazuh nomme le champ dynamique par son chemin SOUS `data.`.
_PREFIX_DATA = "data."
# syscheck est à part : le champ est exposé comme `file` dans les règles FIM.
_FIELD_SYSCHECK = {"syscheck.path": "file"}

_RE_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(text: str, size: int = 40) -> str:
    return _RE_SLUG.sub("-", str(text).lower()).strip("-")[:size] or "signature"


# Ce qu'un commentaire XML ne peut pas contenir sans cesser d'être un
# commentaire : `--` (illégal par la spec) et `<`/`>` (qui permettent d'en
# sortir). Les caractères de contrôle sautent aussi — ils servent à masquer du
# texte à la relecture humaine.
_RE_OUTSIDE_COMMENT = re.compile(r"-{2,}|[<>\x00-\x08\x0b-\x1f\x7f]")


# Caractères qu'un document XML 1.0 ne peut pas porter, même échappés : tous
# les contrôles hors tabulation, retour chariot et saut de ligne.
_RE_XML_FORBIDDEN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _commentable(value, size: int = 200) -> str:
    """Valeur rendue inoffensive dans un commentaire XML.

    Les valeurs de signature (`command`, `file`, `url`, `src_user`) sont écrites
    par les machines surveillées, donc éventuellement par un attaquant. Elles ne
    passent PAS par `saxutils.escape` ici, et il ne le faudrait pas : `escape`
    ne traite pas `--`, qui suffit à fermer un commentaire XML.

    Sans cette neutralisation, une URL contenant `-->` refermait le commentaire
    d'en-tête et le reste de la valeur devenait du XML interprété par le
    manager — soit l'injection d'une règle arbitraire dans le moteur de
    détection, chargée au redémarrage qui suit. Le champ `url` est le pire cas :
    c'est le plus gros contributeur de faux positifs de cette plateforme, et il
    est intégralement choisi par le client qui frappe le reverse proxy.
    """
    text = _RE_OUTSIDE_COMMENT.sub("_", str(value)).replace("\n", " ")
    return text[:size]


# --- construction des conditions --------------------------------------------

def _file_path(raw: dict) -> str | None:
    """Chemin JSON concret d'où vient le champ virtuel « file » pour CE brut.

    « file » n'a pas d'emplacement unique (syscheck, VirusTotal, auditd…). Pour
    écrire une condition de règle il faut le chemin réel, pas le champ virtuel.
    """
    for path in FILE_PATHS:
        if _read(raw, path):
            return path
    return None


def _condition(field: str, value: str, raw: dict) -> str | None:
    """Une ligne XML de condition pour un champ de signature, ou None.

    Ancrée (`^…$`) et échappée : une exception ne doit couvrir QUE la valeur
    observée. Sans ancrage, `<field name="command">rm</field>` exonérerait toute
    commande contenant « rm ».

    Une valeur portant un caractère interdit par XML 1.0 est REFUSÉE (None) :
    `escape()` ne les traite pas, et le fichier produit serait illisible par le
    moteur de règles. L'effet ne serait pas silencieux mais coûteux —
    analysisd refuse de démarrer, `_redemarrer` échoue, le lot entier est retiré
    et le manager redémarre une seconde fois. Refuser en amont vaut mieux.
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
    """XML de la règle fille, ou None si la signature n'est pas traduisible."""
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
        effet = ("Suppression : aucune alerte n'est plus produite pour CETTE "
                 "signature. La règle parente reste entière pour tout le reste.")
    else:
        effet = (f"Sévérité abaissée à {level} : l'alerte existe toujours et "
                 "reste consultable, elle passe simplement sous le seuil "
                 "d'ouverture d'incident. La règle parente reste entière.")

    values = "\n".join(
        f"       - {c} = {_commentable(signature[c])}"
        for c in RULE_DISCRIMINANT_FIELDS if c in signature)

    return f"""<!-- Aura-SOC - rule {rule_id} (level {level}). GÉNÉRÉ AUTOMATIQUEMENT.
     Ne pas éditer à la main : régénéré par `python -m soc_agent.rule_tuning`.
     Convention de nommage et piège d'ordre de chargement : voir rules/README.md
     signature-canonique: {_commentable(_canonical(signature), 400)} -->
<group name="local,soc_ai_auto_tuning,">

  <!-- Exception dérivée de {n_fp} incidents jugés `false_positive` par le
       triage IA (incidents {", ".join(f"#{i}" for i in incidents)}).

       Signature exonérée :
{values}

       {effet}

       Conditions ANCRÉES (`^…$`, pcre2, valeur échappée) : l'exception ne peut
       couvrir que la valeur exacte observée, jamais une variante qui la
       contient. Un attaquant ne peut pas s'y glisser en préfixant ou suffixant
       la valeur.

       Déployée seulement après rejeu `/logtest` prouvant que (a) l'évènement FP
       tombe bien ici et (b) un évènement RÉEL de la même règle parente, avec
       une autre valeur, tombe TOUJOURS sur {parent} à son niveau d'origine. -->

  <rule id="{rule_id}" level="{level}">
    <if_sid>{escape(parent)}</if_sid>
{chr(10).join(conditions)}
    <description>Auto-tuning Aura-SOC: known false positive of rule {escape(parent)}</description>
  </rule>

</group>
"""


# --- API Wazuh : logtest, restart, statut -----------------------------------

def _token() -> str:
    r = requests.post(
        f"{config.WAZUH_API_URL}/security/user/authenticate?raw=true",
        auth=(config.WAZUH_API_USER, config.WAZUH_API_PASSWORD),
        verify=False, timeout=15)
    r.raise_for_status()
    return r.text.strip()


def logtest(tok: str, event: str, location: str) -> tuple[str | None, int | None]:
    """(rule_id, level) rendus par le moteur pour cet évènement, via l'API.

    On passe par l'API et non par le binaire `wazuh-logtest` : ce module tourne
    dans son propre conteneur, sans accès au système de fichiers du manager ni
    au socket Docker.
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
    """Recharge le ruleset. True si le manager est revenu opérationnel.

    Un changement de règle n'est pris en compte qu'au redémarrage du manager —
    d'où la cadence horaire de ce job, et non la minute des autres.
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


# --- sélection des candidats -------------------------------------------------

def _event(raw: dict) -> tuple[str, str] | None:
    """(full_log, location) rejouables, ou None si l'alerte n'est pas rejouable.

    Une alerte sans `full_log` (FIM, rootcheck, modules qui produisent du JSON
    déjà structuré) ne peut pas être rejouée dans logtest — donc pas prouvée,
    donc refusée. Mieux vaut ne rien faire que déployer sans preuve.
    """
    log = raw.get("full_log")
    if not log or "\n" in str(log):
        return None
    return str(log), str(raw.get("location") or "")


def _counter_example(conn, parent: str, signature: dict) -> tuple[str, str] | None:
    """Évènement RÉEL de la même règle parente, mais d'une autre signature.

    C'est lui qui prouve que l'exception ne neutralise pas la règle. Cherché
    parmi les alertes réellement ingérées : un contre-exemple synthétique
    prouverait seulement que la regex écrite tient, pas que la détection tient
    sur le trafic de cet environnement.
    """
    lines = conn.execute(
        "SELECT raw FROM alerts WHERE rule_id = %s "
        "ORDER BY ts DESC LIMIT %s",
        (parent, config.RULE_TUNING_COUNTER_EXAMPLE_CANDIDATES)).fetchall()
    for l in lines:
        raw = l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
        # Une seule valeur différente sur un champ discriminant suffit : cet
        # évènement n'est pas couvert par l'exception, il doit rester détecté.
        if any(str(_value_field(raw, c) or "") != signature[c]
               for c in RULE_DISCRIMINANT_FIELDS if c in signature):
            ev = _event(raw)
            if ev:
                return ev
    return None


def _fp_example(conn, incidents: list[int]) -> tuple[dict, tuple[str, str]] | None:
    """(raw, évènement) d'une alerte représentative des incidents FP."""
    # BORNÉ : on cherche UNE alerte représentative, pas la collection. Sans
    # limite, une liste d'incidents de flood ramenait des centaines de milliers
    # de `raw` complets pour en retenir une seule (1 Go pour 126 508 alertes,
    # cf. whitelist._signature). Les plus récentes d'abord : c'est l'état
    # courant du FP qu'on veut illustrer.
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
    """Signatures canoniques déjà couvertes par une règle générée.

    Les valeurs relues ici sont celles ÉCRITES dans le commentaire, donc passées
    par `_commentable`. La comparaison côté `analyser` applique la même
    transformation : sans cela, toute signature contenant `--`, `<` ou `>` ne se
    reconnaîtrait jamais elle-même et sa règle serait régénérée à chaque
    passage — un redémarrage du manager par cycle, indéfiniment.
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
    raise RuntimeError("plage d'identifiants de règles auto épuisée")


# --- orchestration -----------------------------------------------------------

def analyze(min_fp: int, simulation: bool) -> list[dict]:
    """Génère, prouve et déploie les règles dues. Retourne les décisions."""
    folder = Path(config.RULE_TUNING_DIR)
    if not folder.is_dir():
        raise RuntimeError(f"{folder} introuvable — le répertoire de règles "
                           "du manager doit être monté dans ce conteneur")

    level = config.RULE_TUNING_LEVEL
    if level == 0 and not config.RULE_TUNING_ALLOWED_LEVEL_0:
        raise RuntimeError(
            "RULE_TUNING_NIVEAU=0 (suppression totale) exige "
            "RULE_TUNING_AUTORISE_NIVEAU_0=true")

    decisions: list[dict] = []
    placed: list[tuple[Path, dict]] = []   # (fichier, contexte de vérification)

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_by_sig, sig_tp = _incidents_by_verdict(
            conn, RULE_DISCRIMINANT_FIELDS)
        already = _signatures_already_processed(folder)
        n_existing = len(already)
        tok = _token()

        for canon, e in sorted(fp_by_sig.items()):
            signature, n = e["signature"], len(e["incidents"])

            def refusal(reason):
                decisions.append({"signature": canon, "action": "refusé",
                                  "raison": reason})

            # Comparé sous la forme écrite dans le commentaire (cf.
            # _signatures_deja_traitees), pas sous la forme brute.
            if _commentable(canon, 400) in already:
                continue
            if canon in sig_tp:
                refusal("vue aussi en true_positive"); continue
            if e["max_level"] >= config.WHITELIST_MAX_LEVEL:
                refusal(f"niveau {e['max_level']} >= {config.WHITELIST_MAX_LEVEL}")
                continue
            if n < min_fp:
                decisions.append({"signature": canon, "action": "en attente",
                                  "raison": f"{n}/{min_fp} FP"})
                continue
            if not any(c in signature for c in RULE_DISCRIMINANT_FIELDS):
                refusal("signature trop large : rule_id seul ne suffit pas"); continue
            parent = signature.get("rule_id")
            if not parent:
                refusal("pas de rule_id : impossible de chaîner par if_sid"); continue
            if n_existing + len(placed) >= config.RULE_TUNING_MAX_RULES:
                refusal(f"plafond de {config.RULE_TUNING_MAX_RULES} règles auto atteint")
                continue

            ex = _fp_example(conn, e["incidents"])
            if ex is None:
                refusal("aucune alerte rejouable (pas de full_log)"); continue
            raw_fp, ev_fp = ex

            counter = _counter_example(conn, parent, signature)
            if counter is None:
                refusal("aucun contre-exemple en base : non-invalidation de la "
                      "règle non prouvable"); continue

            # Avant chargement : les deux évènements doivent tomber sur la
            # parente. Sinon la signature ne décrit pas ce qu'on croit, et la
            # vérification d'après serait ininterprétable.
            rid_fp, lvl_fp = logtest(tok, *ev_fp)
            rid_ce, lvl_ce = logtest(tok, *counter)
            if rid_fp != parent:
                refusal(f"rejeu FP tombe sur {rid_fp}, pas sur {parent}"); continue
            if rid_ce != parent:
                refusal(f"rejeu contre-exemple tombe sur {rid_ce}, pas sur {parent}")
                continue

            # Les fichiers du lot ne sont écrits qu'à la fin de la boucle : on
            # décale donc de len(poses) pour ne pas réattribuer le même id.
            rid = _next_id(folder) + len(placed)
            xml = build_xml(rid, parent, level, signature, raw_fp, n,
                                 e["incidents"])
            if xml is None:
                refusal("signature non traduisible en conditions de règle"); continue

            path = folder / f"{rid}-auto-{_slug(canon)}.xml"
            if simulation:
                decisions.append({"signature": canon, "action": "simulé",
                                  "fichier": path.name, "xml": xml, "fp": n})
                continue

            path.write_text(xml, encoding="utf-8")
            placed.append((path, {
                "canon": canon, "parent": parent, "fp": n,
                "ev_fp": ev_fp, "contre": counter,
                "niveau_origine": lvl_ce, "fichier": path.name}))

        if not placed:
            return decisions

        # Un seul redémarrage pour tout le lot : c'est l'opération coûteuse.
        if not _restart(tok):
            for path, ctx in placed:
                path.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "annulé",
                                  "raison": "le manager n'est pas revenu "
                                            "opérationnel — règles retirées"})
            _restart(_token())
            return decisions

        tok = _token()
        to_remove = []
        for path, ctx in placed:
            rid_fp, lvl_fp = logtest(tok, *ctx["ev_fp"])
            rid_ce, lvl_ce = logtest(tok, *ctx["contre"])
            expected = path.name.split("-", 1)[0]

            if rid_fp != expected or lvl_fp != level:
                to_remove.append((path, ctx,
                                  f"l'évènement FP tombe sur {rid_fp} (niveau "
                                  f"{lvl_fp}), attendu {expected} niveau {level}"))
            elif rid_ce != ctx["parent"] or lvl_ce != ctx["niveau_origine"]:
                # LE garde-fou : l'exception a mordu sur autre chose qu'elle.
                to_remove.append((path, ctx,
                                  "INVALIDATION DE LA RÈGLE : le contre-exemple "
                                  f"tombe sur {rid_ce} niveau {lvl_ce} au lieu de "
                                  f"{ctx['parent']} niveau {ctx['niveau_origine']}"))
            else:
                decisions.append({"signature": ctx["canon"], "action": "créé",
                                  "fichier": ctx["fichier"], "fp": ctx["fp"],
                                  "niveau": level, "parent": ctx["parent"]})
                conn.execute(
                    "UPDATE incidents SET status = 'whitelisted' "
                    "WHERE id = ANY(%s)",
                    ([i for i in fp_by_sig[ctx["canon"]]["incidents"]],))
                conn.commit()

        if to_remove:
            for path, ctx, reason in to_remove:
                path.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "annulé",
                                  "raison": reason})
            _restart(_token())

    return decisions


def generated_rules() -> list[dict]:
    """Les règles auto-générées présentes sur disque.

    Le répertoire EST l'état (pas de table) : on relit donc les fichiers plutôt
    qu'une base qui pourrait mentir sur ce que le manager charge vraiment.
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
            "fichier": f.name,
            "rule_id": rid.group(1) if rid else None,
            "niveau": int(rid.group(2)) if rid else None,
            "parent": parent.group(1) if parent else None,
            "signature": canon.group(1).strip() if canon else None,
        })
    return rules


def list() -> None:
    rules = generated_rules()
    if not rules:
        print("Aucune règle générée automatiquement.")
        return
    for r in rules:
        print(f"  {r['fichier']}")
        print(f"      parent {r['parent'] or '?'} -> niveau "
              f"{r['niveau'] if r['niveau'] is not None else '?'}   "
              f"{r['signature'] or ''}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="montre le XML qui serait déployé, ne touche à rien")
    ap.add_argument("--lister", action="store_true")
    args = ap.parse_args()

    if args.list:
        list()
        return

    for d in analyze(args.min_fp, args.simulation):
        if d["action"] == "créé":
            print(f"  CRÉÉ    {d['fichier']}  (parent {d['parent']}, "
                  f"niveau {d['niveau']}, {d['fp']} FP)")
        elif d["action"] == "simulé":
            print(f"  SIMULÉ  {d['fichier']}  ({d['fp']} FP)\n{d['xml']}")
        elif d["action"] == "annulé":
            print(f"  ANNULÉ  {d['signature']} — {d['raison']}")
        elif d["action"] == "refusé":
            print(f"  refusé  {d['signature']} — {d['raison']}")
        else:
            print(f"  attente {d['signature']} — {d['raison']}")


if __name__ == "__main__":
    main()
