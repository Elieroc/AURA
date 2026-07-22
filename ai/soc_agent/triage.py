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
import time
from pathlib import Path

import psycopg
import requests
from psycopg.rows import dict_row

from . import config
from .actions import appliquer_garde_fous, deduire, necessite_validation
from .coherence import verifier
from .render import motifs_injection, rendre

PROMPTS = Path(__file__).parent / "prompts"

# Bornes de sécurité du prompt. Mesuré sur cet hôte : ~50 tokens/s de prefill,
# donc 1500 tokens = 30 s avant le premier token. Dépasser n'est pas une
# dégradation progressive, c'est un budget qui explose.
PLAFOND_TOKENS = 1500

SELECT_INCIDENTS = """
SELECT i.id, i.agent_id, i.agent_name, i.first_seen, i.last_seen,
       i.alert_count, i.max_level, i.rule_ids, i.mitre_tactics, i.entities
  FROM incidents i
 WHERE (%(tous)s OR NOT EXISTS (SELECT 1 FROM triages t WHERE t.incident_id = i.id))
   AND (%(un_seul)s::bigint IS NULL OR i.id = %(un_seul)s)
   AND i.max_level >= %(min_level)s
 ORDER BY i.max_level DESC, i.first_seen DESC
 LIMIT %(limite)s
"""

SELECT_ALERTES = """
SELECT id, ts, rule_id, rule_level, rule_desc, srcip, srcuser, entity, raw
  FROM alerts WHERE incident_id = %s ORDER BY ts
"""


def construire_prompt(incident: dict, alertes: list[dict]) -> tuple[str, str]:
    """(système, utilisateur).

    Le système est strictement constant — consignes et politique de décision.
    C'est ce qui permet au prefix caching de llama.cpp de ne le prefiller
    qu'une fois : ~8,8 s économisées par incident au-delà du premier.
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
    rep = requests.post(f"{config.LLM_URL}/tokenize",
                        json={"content": texte}, timeout=30)
    rep.raise_for_status()
    return len(rep.json()["tokens"])


def interroger(systeme: str, utilisateur: str) -> tuple[dict, dict]:
    """Appelle le modèle. Retourne (verdict, métriques)."""
    grammaire = (PROMPTS / "triage.gbnf").read_text()

    debut = time.monotonic()
    rep = requests.post(
        f"{config.LLM_URL}/v1/chat/completions",
        json={
            # /v1/chat/completions et jamais /completion : le template de chat
            # embarqué dans le GGUF change le verdict (cf. bench/RESULTS.md).
            "messages": [
                {"role": "system", "content": systeme},
                {"role": "user", "content": utilisateur},
            ],
            "grammar": grammaire,
            "max_tokens": 400,
            # Température basse : on veut un verdict reproductible, pas de la
            # variété. Avec la seed fixe, deux passages identiques donnent le
            # même résultat — indispensable pour comparer deux prompts.
            "temperature": 0.2,
            "seed": 42,
            "cache_prompt": True,
        },
        timeout=300,
    )
    rep.raise_for_status()
    corps = rep.json()
    duree_ms = int((time.monotonic() - debut) * 1000)

    # La grammaire garantit la forme : un JSONDecodeError ici signalerait une
    # panne du serveur, pas une sortie inattendue du modèle. On laisse remonter.
    verdict = json.loads(corps["choices"][0]["message"]["content"])

    t = corps.get("usage", {})
    return verdict, {
        "duree_ms": duree_ms,
        "prompt_tokens": t.get("prompt_tokens"),
        "modele": corps.get("model", "?").split("/")[-1],
    }


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
          afficher_prompt: bool) -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        incidents = conn.execute(SELECT_INCIDENTS, {
            "tous": tous, "un_seul": un_seul,
            "min_level": config.MIN_LEVEL, "limite": limite,
        }).fetchall()

        if not incidents:
            print("Aucun incident à trier.")
            return

        for inc in incidents:
            alertes = conn.execute(SELECT_ALERTES, (inc["id"],)).fetchall()
            systeme, utilisateur = construire_prompt(inc, alertes)

            if afficher_prompt:
                print("=" * 70)
                print(utilisateur)
                print("=" * 70)

            n_tokens = compter_tokens(systeme + utilisateur)
            if n_tokens > PLAFOND_TOKENS:
                # On refuse plutôt que de laisser filer : un prompt qui double
                # double le temps de triage, silencieusement.
                print(f"  #{inc['id']} IGNORÉ — prompt de {n_tokens} tokens "
                      f"(plafond {PLAFOND_TOKENS}). Resserrer render.py.")
                continue

            verdict, m = interroger(systeme, utilisateur)

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
            actions, garde_fous = appliquer_garde_fous(
                verdict["verdict"], actions, inc["max_level"], bool(injections))

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
            a_valider = necessite_validation(actions)
            if a_valider:
                print(f"      validation humaine requise : {', '.join(a_valider)}")
            print(f"      {verdict['reason'][:160]}")
            if incoherences:
                print(f"      /!\\ incohérence : {'; '.join(incoherences)}")


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
