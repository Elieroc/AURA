"""Charger les alertes d'un incident sans jamais y laisser la mémoire du cycle.

Un incident de flood aligne des dizaines de milliers d'alertes (126 508 sur un
incident pfSense le 2026-08-14), et chacune porte son `raw` — le JSON complet de
l'alerte Wazuh. `SELECT ... FROM alerts WHERE incident_id = X` est donc une
requête à 186 Mo de JSON en base, bien davantage une fois matérialisée en objets
Python : au-delà du plafond mémoire du conteneur (1 Go), le process est
OOM-killé.

Cette panne s'est produite QUATRE fois, au même endroit logique et à chaque fois
dans un module différent — `iris._alertes`, `whitelist._signature`,
`rule_tuning._exemple_fp`, puis `mitigate.executer`. Chacune a été corrigée
séparément, ce qui n'a jamais empêché la suivante. D'où ce module : le bornage
est un invariant du pipeline, pas une précaution locale à réinventer.

Et la panne est particulièrement sournoise : les jobs tournent dans une boucle
shell (`while true; do python -m soc_agent.X; sleep N; done`), qui SURVIT au kill
du process. Le conteneur reste `Up`, `docker ps` est vert, et le cycle meurt à
chaque passe au même endroit sans jamais rien terminer — ni triage, ni case, ni
remédiation. C'est ce qui s'est produit entre le 2026-08-14 11:24 et 14:20.

Deux stratégies, selon ce que l'appelant fait des lignes :

- `charger_bornees()` quand il lui faut une LISTE en mémoire (ciblage d'une
  remédiation, construction d'un prompt, rendu d'un rapport) ;
- `parcourir()` quand il ne fait que balayer (calcul d'une signature, mise à
  jour ligne à ligne) : curseur serveur, rien n'est matérialisé.
"""

from __future__ import annotations

import logging

from psycopg.rows import tuple_row

from . import config

log = logging.getLogger(__name__)

# Jeux de colonnes utilisés dans le pipeline. Nommés plutôt que passés en clair
# : une chaîne de colonnes construite par l'appelant finirait tôt ou tard par
# être concaténée depuis une variable.
COLONNES_RAPPORT = ("id, ts, rule_id, rule_level, rule_desc, rule_groups, "
                    "mitre_ids, mitre_tactics, srcip, srcuser, entity, raw")
COLONNES_TRIAGE = ("id, ts, rule_id, rule_level, rule_desc, srcip, srcuser, "
                   "entity, raw")
COLONNES_CIBLAGE = "agent_id, agent_name, srcip, srcuser, entity, raw"
COLONNES_UEBA = ("id, ts, agent_id, agent_name, rule_id, srcip, srcuser, "
                 "entity, raw")


def _porte_ts(colonnes: str) -> bool:
    """La colonne `ts` est-elle déjà projetée ? Comparaison sur les noms
    découpés, pas une recherche de sous-chaîne : « rule_groups, mitre_tactics »
    contient « ts » sans porter la colonne."""
    return "ts" in {c.strip() for c in colonnes.split(",")}


def charger_bornees(conn, incident_id: int, colonnes: str,
                    etiquette: str = "") -> list[dict]:
    """Alertes d'un incident, bornées à `config.INCIDENT_MAX_ALERTES`.

    On garde les plus ANCIENNES et les plus RÉCENTES à parts égales. Le début
    porte la graine de l'incident (ce qui a déclenché la corrélation, les cibles
    de l'attaque initiale) et la fin porte l'état courant ; c'est le milieu
    d'une salve répétitive qui n'apprend rien. Prendre « les N dernières »
    perdrait le début de l'attaque, qui est précisément ce qu'un analyste
    cherche.

    La troncature est journalisée en WARNING, jamais silencieuse : sur un
    incident de flood, ce qui est au milieu de la salve n'est pas examiné, et
    cela doit rester lisible. Le compte réel n'est jamais perdu — il vit dans
    `incidents.alert_count`.
    """
    n = conn.execute("SELECT count(*) c FROM alerts WHERE incident_id = %s",
                     (incident_id,)).fetchone()["c"]
    plafond = config.INCIDENT_MAX_ALERTES
    if n <= plafond:
        return conn.execute(
            f"SELECT {colonnes} FROM alerts WHERE incident_id = %s ORDER BY ts",
            (incident_id,)).fetchall()
    moitie = plafond // 2
    log.warning("incident #%s%s : %d alertes, chargement borné à %d "
                "(%d plus anciennes + %d plus récentes) — %d non examinée(s)",
                incident_id, f" ({etiquette})" if etiquette else "",
                n, plafond, moitie, plafond - moitie, n - plafond)
    # `ts` doit figurer dans le SELECT des deux branches, puisque l'ORDER BY
    # final porte dessus — mais SEULEMENT s'il n'y est pas déjà : l'ajouter en
    # aveugle le projette deux fois et Postgres refuse la requête entière
    # (« ORDER BY "ts" is ambiguous »). Trois des quatre jeux de colonnes du
    # pipeline contiennent déjà `ts`, donc le cas nominal est celui-là.
    projection = colonnes if _porte_ts(colonnes) else f"{colonnes}, ts"
    return conn.execute(
        f"(SELECT {projection} FROM alerts WHERE incident_id = %(i)s "
        f" ORDER BY ts ASC LIMIT %(debut)s)"
        # UNION ALL, pas UNION : les deux moitiés sont disjointes par
        # construction (on n'entre ici que si n > plafond), et dédupliquer
        # imposerait un tri sur le `raw` jsonb entier de chaque ligne.
        " UNION ALL "
        f"(SELECT {projection} FROM alerts WHERE incident_id = %(i)s "
        f" ORDER BY ts DESC LIMIT %(fin)s)"
        " ORDER BY ts",
        {"i": incident_id, "debut": moitie, "fin": plafond - moitie}).fetchall()


def parcourir(conn, incident_id: int, colonnes: str, itersize: int = 2000):
    """Générateur sur TOUTES les alertes d'un incident, sans les matérialiser.

    Curseur serveur nommé : Postgres garde le jeu de résultats, le client n'en
    tient que `itersize` lignes à la fois. À préférer à `charger_bornees` dès
    que l'appelant ne fait que balayer — il voit alors l'incident ENTIER sans
    plafond mémoire, ce qui est strictement mieux qu'un échantillon.
    """
    with conn.cursor(name=f"alertes_{incident_id}", row_factory=tuple_row) as cur:
        cur.itersize = itersize
        cur.execute(f"SELECT {colonnes} FROM alerts WHERE incident_id = %s "
                    "ORDER BY ts", (incident_id,))
        yield from cur
