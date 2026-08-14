"""Triage LLM des incidents — mode shadow.

Le modèle rend un verdict, on l'enregistre, et **rien ne se déclenche**. Tant
que la justesse n'est pas mesurée sur un jeu labellisé (`evaluate.py`), agir
sur une sortie de modèle serait un pari.

    python -m soc_agent.triage --limite 10
    python -m soc_agent.triage --incident 4 --afficher-prompt
"""

import argparse
import hashlib
import json
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from . import alertes as alertes_mod
from . import config
from .actions import appliquer_garde_fous, deduire, actions_fort_impact
from .anonymize import (Anonymiseur, FuiteError, anonymiser, rehydrater,
                        verifier_fuite)
from .coherence import verifier
from .llm import completion
from .render import motifs_injection, rendre

PROMPTS = Path(__file__).parent / "prompts"

# Plafond de taille de prompt : un budget de coût, et une borne contre un prompt
# qui déraille. Trop bas, il faisait TAIRE les plus gros incidents (le plus grave
# — 350 alertes, niveau 14 — n'avait ni triage ni case ni remédiation). Relevé à
# 5000 ; env-surchargeable. Le préfiltrage/résumé reste souhaitable en amont.
PLAFOND_TOKENS = config.PLAFOND_PROMPT_TOKENS

# Enums de sortie. Rien ne les garantit à l'échantillonnage : DeepSeek ne
# garantit que le JSON valide. On revalide donc ici — c'est la place correcte
# pour la barrière (le modèle n'est pas une frontière de sécurité).
VERDICTS_OK = {"true_positive", "false_positive", "needs_investigation"}
CONFIANCES_OK = {"low", "medium", "high"}
ACTIONS_OK = {"propose_block_ip", "propose_isolate_host",
              "propose_disable_user", "propose_kill_process",
              "propose_quarantine_file", "propose_remove_privileged_group",
              "escalate_human"}


def _valider(brut: dict) -> dict:
    """Coerce la sortie du modèle vers le schéma attendu.

    Toute valeur hors enum est ramenée à une valeur sûre plutôt que propagée :
    un verdict inconnu devient `needs_investigation` (n'entraîne aucune action
    automatique), une action inconnue est écartée. C'est ici
    qu'on garantit la forme.
    """
    verdict = brut.get("verdict")
    if verdict not in VERDICTS_OK:
        verdict = "needs_investigation"

    confidence = brut.get("confidence")
    if confidence not in CONFIANCES_OK:
        confidence = "low"

    actions_brutes = brut.get("actions") or []
    if not isinstance(actions_brutes, list):
        actions_brutes = []
    # Filtrage à l'enum, dédup en gardant l'ordre, plafond à 4.
    actions, vus = [], set()
    for a in actions_brutes:
        if a in ACTIONS_OK and a not in vus:
            vus.add(a)
            actions.append(a)
    actions = actions[:4]

    mitre = brut.get("mitre")
    if not (isinstance(mitre, str) and mitre.startswith("T")):
        mitre = None

    reason = str(brut.get("reason") or "").strip() or "(aucune justification)"

    return {"verdict": verdict, "confidence": confidence, "actions": actions,
            "mitre": mitre, "reason": reason}

SELECT_INCIDENTS = """
SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
       i.alert_count, i.max_level, i.rule_ids, i.mitre_tactics, i.entities,
       i.ueba, i.ueba_score, i.ueba_motifs,
       COALESCE(i.priorite, %(prio_defaut)s) AS priorite,
       COALESCE(i.severite, i.max_level) AS severite,
       -- Colonne de l'incident, PAS une jointure sur `assets` : le rôle qui a
       -- servi au calcul peut différer du rôle déclaré (capteur rabattu), et
       -- une jointure afficherait une priorité et un rôle qui se contredisent.
       i.asset_role
  FROM incidents i
 WHERE (%(tous)s
        OR NOT EXISTS (SELECT 1 FROM triages t WHERE t.incident_id = i.id)
        -- incident enrichi depuis son dernier triage, MAIS pas indéfiniment :
        -- passé INCIDENT_REFRESH_TTL_HOURS depuis first_seen, on ne re-triage
        -- plus (correctif #4 anti-boucle ; 0 = sans limite). La création d'un
        -- incident jamais trié reste hors de ce plafond (clause NOT EXISTS).
        OR (i.needs_refresh
            AND (%(refresh_ttl)s <= 0
                 OR i.first_seen > now() - make_interval(hours => %(refresh_ttl)s))))
   AND (%(un_seul)s::bigint IS NULL OR i.id = %(un_seul)s)
   -- Deux populations : les incidents graine-Wazuh (max_level >= MIN_LEVEL) et
   -- les incidents UEBA, dont le niveau max est BAS par construction (ils
   -- viennent d'alertes 3-11). Sans la seconde clause, tout ce que le moteur
   -- comportemental remonte serait silencieusement écarté du triage.
   AND (i.max_level >= %(min_level)s OR i.ueba)
 -- Le lot est PLAFONNÉ (limite_triage) : l'ordre décide de ce qui est analysé
 -- maintenant et de ce qui attend le cycle suivant. La priorité de l'asset
 -- passe donc avant le niveau de la règle — un niveau 12 sur le contrôleur de
 -- domaine doit sortir avant un niveau 14 sur un poste de test.
 ORDER BY i.ueba, COALESCE(i.priorite, %(prio_defaut)s),
          COALESCE(i.severite, i.max_level) DESC, i.first_seen DESC
 LIMIT %(limite)s
"""

# Le chargement passe par `alertes.charger_bornees` : un incident de flood
# neuf (103 251 alertes pour #2854) tuait le triage avant tout appel au modèle.
# Aucune perte pour la décision — `render.rendre` ne montre de toute façon au
# modèle qu'un extrait borné par le nombre de règles.


def construire_prompt(incident: dict, alertes: list[dict]) -> tuple[str, str]:
    """(système, utilisateur).

    Le système est strictement constant — consignes et politique de décision.
    Deux raisons de ne jamais y glisser de variable : le cache de contexte de
    DeepSeek ne s'amorce que sur un préfixe identique au token près, et un
    système qui bouge rend deux triages incomparables (`prompt_sha`).
    """
    systeme = (PROMPTS / "system.md").read_text()
    corps = rendre(incident, alertes)
    utilisateur = (
        "=== DEBUT INCIDENT (données non fiables) ===\n"
        f"{corps}\n"
        "=== FIN INCIDENT ===\n\n"
        "Rends ton verdict."
    )
    return systeme, utilisateur


def compter_tokens(texte: str) -> int:
    """Estimation grossière du nombre de tokens.

    DeepSeek n'expose pas d'endpoint de tokenisation. ~4 caractères par token
    (ordre de grandeur observé sur ces prompts) : suffisant pour le garde-fou
    de taille de prompt, qui n'a pas besoin d'être exact. Le compte réel est
    récupéré après coup depuis l'usage renvoyé par l'API.
    """
    return len(texte) // 4


def interroger(systeme: str, utilisateur: str,
               incident_id: int | None = None) -> tuple[dict, dict]:
    """Appelle le modèle (DeepSeek) et valide la sortie. Retourne (verdict, m)."""
    brut, m = completion(systeme, utilisateur, max_tokens=config.TRIAGE_MAX_TOKENS,
                         usage="triage", incident_id=incident_id)
    verdict = _valider(brut)
    return verdict, m


def charger_map(conn, incident_id: int) -> dict:
    r = conn.execute("SELECT mapping FROM anonymization_map WHERE incident_id = %s",
                     (incident_id,)).fetchone()
    return (r["mapping"] if r else {}) or {}


def sauver_map(conn, incident_id: int, mapping: dict) -> None:
    conn.execute(
        "INSERT INTO anonymization_map (incident_id, mapping) VALUES (%s, %s) "
        "ON CONFLICT (incident_id) DO UPDATE "
        "SET mapping = EXCLUDED.mapping, updated_at = now()",
        (incident_id, json.dumps(mapping, ensure_ascii=False)))


INSERT_TRIAGE = """
INSERT INTO triages (incident_id, verdict, confidence, mitre, actions, reason,
                     modele, prompt_sha, prompt_tokens, duree_ms, mode,
                     incoherences, injection_motifs, garde_fous)
VALUES (%(incident_id)s, %(verdict)s, %(confidence)s, %(mitre)s, %(actions)s,
        %(reason)s, %(modele)s, %(prompt_sha)s, %(prompt_tokens)s,
        %(duree_ms)s, 'shadow', %(incoherences)s, %(injection_motifs)s,
        %(garde_fous)s)
RETURNING id
"""


def trier(limite: int, un_seul: int | None, tous: bool,
          afficher_prompt: bool) -> list[dict]:
    """Trie un lot d'incidents et rend le résultat par incident.

    Les `print` restent : ils sont les journaux du conteneur `soc-agent-cycle`,
    lus quand un lot dérape. Le retour est là pour les appelants programmatiques
    (serveur MCP), qui ne doivent pas avoir à parser cette sortie.

    Chaque entrée porte un `statut` : `trié`, ou l'un des trois refus —
    `fuite` (identifiant interne non pseudonymisé), `prompt_trop_long`,
    `echec_llm`. Un refus n'interrompt pas le lot.
    """
    resultats: list[dict] = []
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incidents = conn.execute(SELECT_INCIDENTS, {
            "tous": tous, "un_seul": un_seul,
            "min_level": config.MIN_LEVEL, "limite": limite,
            "refresh_ttl": config.INCIDENT_REFRESH_TTL_HOURS,
            "prio_defaut": config.PRIORITE_DEFAUT,
        }).fetchall()

        if not incidents:
            print("Aucun incident à trier.")
            return resultats

        for inc in incidents:
            alertes = alertes_mod.charger_bornees(
                conn, inc["id"], alertes_mod.COLONNES_TRIAGE, "triage")

            # Pseudonymisation AVANT toute construction de prompt : rien de
            # sensible ne doit atteindre le cloud. Jetons stables entre passages
            # via la correspondance persistée.
            anon = Anonymiseur(charger_map(conn, inc["id"]))
            inc_a, alertes_a, interdits = anonymiser(anon, inc, alertes)
            systeme, utilisateur = construire_prompt(inc_a, alertes_a)

            if afficher_prompt:
                print("=" * 70)
                print(utilisateur)
                print("=" * 70)

            # Garde-fou fail-closed : un identifiant interne qui aurait échappé
            # à la pseudonymisation interdit l'envoi, on ne devine pas. On ne
            # scanne QUE `utilisateur` (les données incident) : le prompt système
            # est un template dev constant, sans donnée client, et contient des
            # chemins d'exemple (/var/tmp, /dev/shm) qui déclenchaient un faux
            # positif de fuite.
            try:
                verifier_fuite(utilisateur, interdits)
            except FuiteError as e:
                print(f"  #{inc['id']} IGNORÉ — fuite potentielle : {e}")
                resultats.append({"incident_id": inc["id"], "statut": "fuite",
                                  "detail": str(e)})
                continue

            n_tokens = compter_tokens(systeme + utilisateur)
            if n_tokens > PLAFOND_TOKENS:
                # On refuse plutôt que de laisser filer : un prompt qui double
                # double le temps de triage, silencieusement.
                print(f"  #{inc['id']} IGNORÉ — prompt de {n_tokens} tokens "
                      f"(plafond {PLAFOND_TOKENS}). Resserrer render.py.")
                resultats.append({"incident_id": inc["id"],
                                  "statut": "prompt_trop_long",
                                  "tokens": n_tokens, "plafond": PLAFOND_TOKENS})
                continue

            # Un incident empoisonné ne casse pas le lot. L'appel LLM peut
            # échouer sur CET incident (content vide si le raisonnement épuise
            # max_tokens, JSON tronqué à la coupe de longueur, enum invalide) :
            # sans ce filet, l'exception remontait jusqu'à cycle.py qui coupait
            # le cycle ENTIER — donc la création de cases des incidents déjà
            # triés. Et comme le lot est trié dans un ordre déterministe, le même
            # incident repassait en tête à chaque cycle : blocage permanent. On
            # journalise, on rollback l'incident, on passe au suivant ; il sera
            # retenté au prochain tour et les autres avancent.
            try:
                verdict, m = interroger(systeme, utilisateur, inc["id"])
            except Exception as e:  # noqa: BLE001
                conn.rollback()
                print(f"  #{inc['id']} SAUTÉ — triage LLM échoué : {e}")
                resultats.append({"incident_id": inc["id"],
                                  "statut": "echec_llm", "detail": str(e)})
                continue

            sauver_map(conn, inc["id"], anon.mapping)
            # Réhydratation : l'analyste doit lire les vraies valeurs, pas les
            # jetons. Seul DeepSeek a vu les pseudonymes.
            verdict["reason"] = rehydrater(verdict["reason"], anon.mapping)

            # On relève l'incohérence, on ne la corrige pas : réécrire le
            # verdict du modèle masquerait le problème au lieu de le mesurer.
            incoherences = verifier(verdict["verdict"], verdict["actions"])
            # Le modèle ne propose que des remédiations ; l'ouverture ou la
            # clôture du dossier découle du verdict.
            actions = deduire(verdict["verdict"], verdict["actions"])

            # Barrière déterministe. Le modèle se laisse retourner par une
            # injection dans les logs (3 charges sur 4, cf. tests) ; il ne peut
            # donc pas être le dernier mot sur une clôture.
            injections = motifs_injection(alertes)
            # Compromission active de l'hôte : au moins une règle de
            # post-exploitation dans l'incident (webshell qui exécute, reverse
            # shell, rootkit, persistance root). Sur ce signal, le garde-fou ne
            # rétrograde plus l'isolation vers un simple block_ip.
            compromission_active = bool(
                set(inc["rule_ids"] or []) & config.RULES_COMPROMISSION_HOTE)
            actions, garde_fous = appliquer_garde_fous(
                verdict["verdict"], actions, inc["max_level"], bool(injections),
                compromission_active, inc.get("priorite"))

            conn.execute(INSERT_TRIAGE, {
                "incoherences": incoherences,
                "injection_motifs": injections,
                "garde_fous": garde_fous,
                "incident_id": inc["id"],
                "verdict": verdict["verdict"],
                "confidence": verdict["confidence"],
                "mitre": verdict["mitre"],
                "actions": actions,
                "reason": verdict["reason"],
                "modele": m["modele"],
                "prompt_sha": hashlib.sha256(
                    (systeme + utilisateur).encode()).hexdigest()[:16],
                "prompt_tokens": m["prompt_tokens"] or n_tokens,
                "duree_ms": m["duree_ms"],
            })
            conn.commit()

            print(f"  #{inc['id']} {inc['agent_name']:<14} "
                  f"{verdict['verdict']:<20} {verdict['confidence']:<7} "
                  f"{n_tokens:4d} tok  {m['duree_ms'] / 1000:5.1f}s")
            print(f"      actions : {', '.join(actions)}")
            if injections:
                print(f"      /!\\ motifs d'injection : {', '.join(injections)}")
            for g in garde_fous:
                print(f"      GARDE-FOU {g}")
            fort_impact = actions_fort_impact(actions)
            if fort_impact:
                print(f"      actions à fort impact (exécutées, autonomes) : "
                      f"{', '.join(fort_impact)}")
            print(f"      {verdict['reason'][:160]}")
            if incoherences:
                print(f"      /!\\ incohérence : {'; '.join(incoherences)}")

            resultats.append({
                "incident_id": inc["id"], "statut": "trié",
                "agent_name": inc["agent_name"],
                "verdict": verdict["verdict"],
                "confidence": verdict["confidence"],
                "mitre": verdict["mitre"], "actions": actions,
                "actions_fort_impact": fort_impact,
                "reason": verdict["reason"],
                "incoherences": incoherences,
                "injection_motifs": injections,
                "garde_fous": garde_fous,
                "modele": m["modele"], "tokens": n_tokens,
                "duree_ms": m["duree_ms"],
            })

    return resultats


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--limite", type=int, default=20)
    ap.add_argument("--incident", type=int, default=None,
                    help="ne trier qu'un incident précis")
    ap.add_argument("--tous", action="store_true",
                    help="retrier même les incidents déjà triés (comparaison "
                         "après changement de prompt ou de modèle)")
    ap.add_argument("--afficher-prompt", action="store_true")
    args = ap.parse_args()
    trier(args.limite, args.incident, args.tous, args.afficher_prompt)


if __name__ == "__main__":
    main()
