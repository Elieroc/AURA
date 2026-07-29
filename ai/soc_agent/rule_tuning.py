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
from .noise import CHAMP, FICHIER_CHEMINS, _lire, _valeur_champ
from .whitelist import (CHAMPS_DISCRIMINANTS, _canonique, _incidents_par_verdict)

requests.packages.urllib3.disable_warnings()  # certificats auto-signés en local


# Correspondance champ de signature -> option de règle Wazuh. Point de départ
# seulement : ce qui tranche, c'est le rejeu logtest (cf. docstring).
#
# `srcuser` n'a PAS de forme `<field name="srcuser">` : c'est un champ statique
# du moteur, il lève « Field 'srcuser' is static » au chargement. Son option
# dédiée est `<user>`.
_OPTION_STATIQUE = {
    "src_user": "user",
    "dst_user": "user",
    "url": "url",
}

# Discriminants acceptés ici, un de plus que la whitelist post-retrieval :
# `url`. C'est LE champ des faux positifs web, et de loin le plus gros
# contributeur de charge sur cette plateforme (un reverse proxy exposé sur
# internet). Le filtre post-retrieval ne peut rien en faire d'utile — l'alerte
# est déjà produite et indexée quand il s'exécute ; une règle fille, si.
CHAMPS_DISCRIMINANTS_REGLE = CHAMPS_DISCRIMINANTS + ("url",)
# Chemin JSON (data.X) -> nom de champ dynamique tel qu'écrit dans une règle.
# Wazuh nomme le champ dynamique par son chemin SOUS `data.`.
_PREFIXE_DATA = "data."
# syscheck est à part : le champ est exposé comme `file` dans les règles FIM.
_CHAMP_SYSCHECK = {"syscheck.path": "file"}

_RE_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(texte: str, taille: int = 40) -> str:
    return _RE_SLUG.sub("-", str(texte).lower()).strip("-")[:taille] or "signature"


# --- construction des conditions --------------------------------------------

def _chemin_fichier(raw: dict) -> str | None:
    """Chemin JSON concret d'où vient le champ virtuel « file » pour CE brut.

    « file » n'a pas d'emplacement unique (syscheck, VirusTotal, auditd…). Pour
    écrire une condition de règle il faut le chemin réel, pas le champ virtuel.
    """
    for chemin in FICHIER_CHEMINS:
        if _lire(raw, chemin):
            return chemin
    return None


def _condition(champ: str, valeur: str, raw: dict) -> str | None:
    """Une ligne XML de condition pour un champ de signature, ou None.

    Ancrée (`^…$`) et échappée : une exception ne doit couvrir QUE la valeur
    observée. Sans ancrage, `<field name="command">rm</field>` exonérerait toute
    commande contenant « rm ».
    """
    motif = f"^{re.escape(valeur)}$"
    option = _OPTION_STATIQUE.get(champ)
    if option:
        return f'    <{option} type="pcre2">{escape(motif)}</{option}>'

    if champ == "file":
        chemin = _chemin_fichier(raw)
        if not chemin:
            return None
        nom = _CHAMP_SYSCHECK.get(chemin) or chemin.removeprefix(_PREFIXE_DATA)
    else:
        chemin = CHAMP.get(champ, champ)
        nom = chemin.removeprefix(_PREFIXE_DATA)

    return (f'    <field name="{escape(nom)}" type="pcre2">'
            f'{escape(motif)}</field>')


def construire_xml(rule_id: int, parent: str, niveau: int, signature: dict,
                   raw: dict, n_fp: int, incidents: list[int]) -> str | None:
    """XML de la règle fille, ou None si la signature n'est pas traduisible."""
    conditions = []
    for champ in CHAMPS_DISCRIMINANTS_REGLE:
        if champ in signature:
            ligne = _condition(champ, signature[champ], raw)
            if ligne is None:
                return None
            conditions.append(ligne)
    if not conditions:
        return None

    if niveau == 0:
        effet = ("Suppression : aucune alerte n'est plus produite pour CETTE "
                 "signature. La règle parente reste entière pour tout le reste.")
    else:
        effet = (f"Sévérité abaissée à {niveau} : l'alerte existe toujours et "
                 "reste consultable, elle passe simplement sous le seuil "
                 "d'ouverture d'incident. La règle parente reste entière.")

    valeurs = "\n".join(
        f"       - {c} = {signature[c]}"
        for c in CHAMPS_DISCRIMINANTS_REGLE if c in signature)

    return f"""<!-- SOC-AI - rule {rule_id} (level {niveau}). GÉNÉRÉ AUTOMATIQUEMENT.
     Ne pas éditer à la main : régénéré par `python -m soc_agent.rule_tuning`.
     Convention de nommage et piège d'ordre de chargement : voir rules/README.md
     signature-canonique: {_canonique(signature)} -->
<group name="local,soc_ai_auto_tuning,">

  <!-- Exception dérivée de {n_fp} incidents jugés `false_positive` par le
       triage IA (incidents {", ".join(f"#{i}" for i in incidents)}).

       Signature exonérée :
{valeurs}

       {effet}

       Conditions ANCRÉES (`^…$`, pcre2, valeur échappée) : l'exception ne peut
       couvrir que la valeur exacte observée, jamais une variante qui la
       contient. Un attaquant ne peut pas s'y glisser en préfixant ou suffixant
       la valeur.

       Déployée seulement après rejeu `/logtest` prouvant que (a) l'évènement FP
       tombe bien ici et (b) un évènement RÉEL de la même règle parente, avec
       une autre valeur, tombe TOUJOURS sur {parent} à son niveau d'origine. -->

  <rule id="{rule_id}" level="{niveau}">
    <if_sid>{escape(parent)}</if_sid>
{chr(10).join(conditions)}
    <description>Auto-tuning SOC-AI: known false positive of rule {escape(parent)}</description>
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
    regle = (((r.json().get("data") or {}).get("output") or {}).get("rule") or {})
    niveau = regle.get("level")
    return regle.get("id"), (int(niveau) if niveau is not None else None)


def _redemarrer(tok: str) -> bool:
    """Recharge le ruleset. True si le manager est revenu opérationnel.

    Un changement de règle n'est pris en compte qu'au redémarrage du manager —
    d'où la cadence horaire de ce job, et non la minute des autres.
    """
    r = requests.put(f"{config.WAZUH_API_URL}/manager/restart",
                     headers={"Authorization": f"Bearer {tok}"},
                     verify=False, timeout=60)
    r.raise_for_status()
    for _ in range(config.RULE_TUNING_ATTENTE_ESSAIS):
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

def _evenement(raw: dict) -> tuple[str, str] | None:
    """(full_log, location) rejouables, ou None si l'alerte n'est pas rejouable.

    Une alerte sans `full_log` (FIM, rootcheck, modules qui produisent du JSON
    déjà structuré) ne peut pas être rejouée dans logtest — donc pas prouvée,
    donc refusée. Mieux vaut ne rien faire que déployer sans preuve.
    """
    log = raw.get("full_log")
    if not log or "\n" in str(log):
        return None
    return str(log), str(raw.get("location") or "")


def _contre_exemple(conn, parent: str, signature: dict) -> tuple[str, str] | None:
    """Évènement RÉEL de la même règle parente, mais d'une autre signature.

    C'est lui qui prouve que l'exception ne neutralise pas la règle. Cherché
    parmi les alertes réellement ingérées : un contre-exemple synthétique
    prouverait seulement que la regex écrite tient, pas que la détection tient
    sur le trafic de cet environnement.
    """
    lignes = conn.execute(
        "SELECT raw FROM alerts WHERE rule_id = %s "
        "ORDER BY ts DESC LIMIT %s",
        (parent, config.RULE_TUNING_CANDIDATS_CONTRE_EXEMPLE)).fetchall()
    for l in lignes:
        raw = l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
        # Une seule valeur différente sur un champ discriminant suffit : cet
        # évènement n'est pas couvert par l'exception, il doit rester détecté.
        if any(str(_valeur_champ(raw, c) or "") != signature[c]
               for c in CHAMPS_DISCRIMINANTS_REGLE if c in signature):
            ev = _evenement(raw)
            if ev:
                return ev
    return None


def _exemple_fp(conn, incidents: list[int]) -> tuple[dict, tuple[str, str]] | None:
    """(raw, évènement) d'une alerte représentative des incidents FP."""
    lignes = conn.execute(
        "SELECT raw FROM alerts WHERE incident_id = ANY(%s) ORDER BY ts DESC",
        (incidents,)).fetchall()
    for l in lignes:
        raw = l["raw"] if isinstance(l["raw"], dict) else json.loads(l["raw"])
        ev = _evenement(raw)
        if ev:
            return raw, ev
    return None


def _signatures_deja_traitees(dossier: Path) -> set[str]:
    """Signatures canoniques déjà couvertes par une règle générée."""
    vues: set[str] = set()
    for f in dossier.glob("*.xml"):
        texte = f.read_text(encoding="utf-8", errors="replace")
        m = re.search(r"signature-canonique: (.+)", texte)
        if m:
            vues.add(m.group(1).strip())
    return vues


def _prochain_id(dossier: Path) -> int:
    utilises = {int(m.group(1))
                for f in dossier.glob("*.xml")
                if (m := re.match(r"^(\d+)-", f.name))}
    for rid in range(config.RULE_TUNING_ID_MIN, config.RULE_TUNING_ID_MAX + 1):
        if rid not in utilises:
            return rid
    raise RuntimeError("plage d'identifiants de règles auto épuisée")


# --- orchestration -----------------------------------------------------------

def analyser(min_fp: int, simulation: bool) -> list[dict]:
    """Génère, prouve et déploie les règles dues. Retourne les décisions."""
    dossier = Path(config.RULE_TUNING_DIR)
    if not dossier.is_dir():
        raise RuntimeError(f"{dossier} introuvable — le répertoire de règles "
                           "du manager doit être monté dans ce conteneur")

    niveau = config.RULE_TUNING_NIVEAU
    if niveau == 0 and not config.RULE_TUNING_AUTORISE_NIVEAU_0:
        raise RuntimeError(
            "RULE_TUNING_NIVEAU=0 (suppression totale) exige "
            "RULE_TUNING_AUTORISE_NIVEAU_0=true")

    decisions: list[dict] = []
    poses: list[tuple[Path, dict]] = []   # (fichier, contexte de vérification)

    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        fp_par_sig, sig_tp = _incidents_par_verdict(
            conn, CHAMPS_DISCRIMINANTS_REGLE)
        deja = _signatures_deja_traitees(dossier)
        n_existantes = len(deja)
        tok = _token()

        for canon, e in sorted(fp_par_sig.items()):
            signature, n = e["signature"], len(e["incidents"])

            def refus(raison):
                decisions.append({"signature": canon, "action": "refusé",
                                  "raison": raison})

            if canon in deja:
                continue
            if canon in sig_tp:
                refus("vue aussi en true_positive"); continue
            if e["max_level"] >= config.WHITELIST_MAX_LEVEL:
                refus(f"niveau {e['max_level']} >= {config.WHITELIST_MAX_LEVEL}")
                continue
            if n < min_fp:
                decisions.append({"signature": canon, "action": "en attente",
                                  "raison": f"{n}/{min_fp} FP"})
                continue
            if not any(c in signature for c in CHAMPS_DISCRIMINANTS_REGLE):
                refus("signature trop large : rule_id seul ne suffit pas"); continue
            parent = signature.get("rule_id")
            if not parent:
                refus("pas de rule_id : impossible de chaîner par if_sid"); continue
            if n_existantes + len(poses) >= config.RULE_TUNING_MAX_REGLES:
                refus(f"plafond de {config.RULE_TUNING_MAX_REGLES} règles auto atteint")
                continue

            ex = _exemple_fp(conn, e["incidents"])
            if ex is None:
                refus("aucune alerte rejouable (pas de full_log)"); continue
            raw_fp, ev_fp = ex

            contre = _contre_exemple(conn, parent, signature)
            if contre is None:
                refus("aucun contre-exemple en base : non-invalidation de la "
                      "règle non prouvable"); continue

            # Avant chargement : les deux évènements doivent tomber sur la
            # parente. Sinon la signature ne décrit pas ce qu'on croit, et la
            # vérification d'après serait ininterprétable.
            rid_fp, niv_fp = logtest(tok, *ev_fp)
            rid_ce, niv_ce = logtest(tok, *contre)
            if rid_fp != parent:
                refus(f"rejeu FP tombe sur {rid_fp}, pas sur {parent}"); continue
            if rid_ce != parent:
                refus(f"rejeu contre-exemple tombe sur {rid_ce}, pas sur {parent}")
                continue

            # Les fichiers du lot ne sont écrits qu'à la fin de la boucle : on
            # décale donc de len(poses) pour ne pas réattribuer le même id.
            rid = _prochain_id(dossier) + len(poses)
            xml = construire_xml(rid, parent, niveau, signature, raw_fp, n,
                                 e["incidents"])
            if xml is None:
                refus("signature non traduisible en conditions de règle"); continue

            chemin = dossier / f"{rid}-auto-{_slug(canon)}.xml"
            if simulation:
                decisions.append({"signature": canon, "action": "simulé",
                                  "fichier": chemin.name, "xml": xml, "fp": n})
                continue

            chemin.write_text(xml, encoding="utf-8")
            poses.append((chemin, {
                "canon": canon, "parent": parent, "fp": n,
                "ev_fp": ev_fp, "contre": contre,
                "niveau_origine": niv_ce, "fichier": chemin.name}))

        if not poses:
            return decisions

        # Un seul redémarrage pour tout le lot : c'est l'opération coûteuse.
        if not _redemarrer(tok):
            for chemin, ctx in poses:
                chemin.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "annulé",
                                  "raison": "le manager n'est pas revenu "
                                            "opérationnel — règles retirées"})
            _redemarrer(_token())
            return decisions

        tok = _token()
        a_retirer = []
        for chemin, ctx in poses:
            rid_fp, niv_fp = logtest(tok, *ctx["ev_fp"])
            rid_ce, niv_ce = logtest(tok, *ctx["contre"])
            attendu = chemin.name.split("-", 1)[0]

            if rid_fp != attendu or niv_fp != niveau:
                a_retirer.append((chemin, ctx,
                                  f"l'évènement FP tombe sur {rid_fp} (niveau "
                                  f"{niv_fp}), attendu {attendu} niveau {niveau}"))
            elif rid_ce != ctx["parent"] or niv_ce != ctx["niveau_origine"]:
                # LE garde-fou : l'exception a mordu sur autre chose qu'elle.
                a_retirer.append((chemin, ctx,
                                  "INVALIDATION DE LA RÈGLE : le contre-exemple "
                                  f"tombe sur {rid_ce} niveau {niv_ce} au lieu de "
                                  f"{ctx['parent']} niveau {ctx['niveau_origine']}"))
            else:
                decisions.append({"signature": ctx["canon"], "action": "créé",
                                  "fichier": ctx["fichier"], "fp": ctx["fp"],
                                  "niveau": niveau, "parent": ctx["parent"]})
                conn.execute(
                    "UPDATE incidents SET status = 'whitelisted' "
                    "WHERE id = ANY(%s)",
                    ([i for i in fp_par_sig[ctx["canon"]]["incidents"]],))
                conn.commit()

        if a_retirer:
            for chemin, ctx, raison in a_retirer:
                chemin.unlink(missing_ok=True)
                decisions.append({"signature": ctx["canon"], "action": "annulé",
                                  "raison": raison})
            _redemarrer(_token())

    return decisions


def lister() -> None:
    dossier = Path(config.RULE_TUNING_DIR)
    fichiers = sorted(dossier.glob("*-auto-*.xml")) if dossier.is_dir() else []
    if not fichiers:
        print("Aucune règle générée automatiquement.")
        return
    for f in fichiers:
        texte = f.read_text(encoding="utf-8", errors="replace")
        niveau = re.search(r'<rule id="\d+" level="(\d+)"', texte)
        parent = re.search(r"<if_sid>([^<]+)</if_sid>", texte)
        canon = re.search(r"signature-canonique: (.+)", texte)
        print(f"  {f.name}")
        print(f"      parent {parent.group(1) if parent else '?'} -> niveau "
              f"{niveau.group(1) if niveau else '?'}   "
              f"{canon.group(1).strip() if canon else ''}")


def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--min-fp", type=int, default=config.WHITELIST_MIN_FP)
    ap.add_argument("--simulation", action="store_true",
                    help="montre le XML qui serait déployé, ne touche à rien")
    ap.add_argument("--lister", action="store_true")
    args = ap.parse_args()

    if args.lister:
        lister()
        return

    for d in analyser(args.min_fp, args.simulation):
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
