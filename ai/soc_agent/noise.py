"""Filtrage du bruit, à deux niveaux (cf. noise_filter.yaml).

Séparation nette entre les deux étages :

- `clauses_must_not()` produit les filtres poussés dans la requête à l'indexer.
  Ces alertes ne sont jamais ingérées. On les écarte au plus tôt, là où c'est
  le moins cher.
- `raison_suppression()` juge une alerte déjà récupérée. Elle sera ingérée et
  conservée pour l'audit, mais marquée et exclue de la corrélation.

Le même critère (une IP, un compte, une règle) peut appartenir à l'un ou
l'autre étage selon son `query_level`, décidé dans le YAML. Ici on ne fait
qu'appliquer ; la politique est dans le fichier de config.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

CONFIG_DEFAUT = Path(__file__).parent / "noise_filter.yaml"

# Champ Wazuh visé par chaque type d'entrée simple. Sert des deux côtés : à
# construire le must_not (chemin OpenSearch) et à lire la valeur dans le
# document brut (même chemin, notation pointée).
CHAMP = {
    "rule_id": "rule.id",
    "src_user": "data.srcuser",
    "dst_user": "data.dstuser",
    "command": "data.command",
    "agent_name": "agent.name",
    "agent_id": "agent.id",
}


def _lire(src: dict, chemin: str):
    """Valeur d'un champ Wazuh en notation pointée dans le document brut."""
    noeud = src
    for cle in chemin.split("."):
        if not isinstance(noeud, dict):
            return None
        noeud = noeud.get(cle)
        if noeud is None:
            return None
    return noeud


class NoiseFilter:
    """Règles de filtrage chargées depuis le YAML.

    Chaque entrée simple devient un triplet (type, valeur, reason) rangé selon
    son query_level. Les composites sont toujours post-retrieval.
    """

    def __init__(self, config: dict):
        self.query_level: list[tuple[str, str, str]] = []
        self.post: list[tuple[str, str, str]] = []
        self.composites: list[dict] = []
        self._charger(config.get("filters", {}))

    def _ajouter(self, type_champ: str, valeur, query_level: bool, reason: str):
        cible = self.query_level if query_level else self.post
        cible.append((type_champ, str(valeur), reason or type_champ))

    def _charger(self, f: dict) -> None:
        for e in f.get("rules", {}).get("ignore_rule_ids") or []:
            self._ajouter("rule_id", e["id"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("actors", {}).get("ignore_src_users") or []:
            self._ajouter("src_user", e["user"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("destinations", {}).get("ignore_dst_users") or []:
            self._ajouter("dst_user", e["user"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in f.get("commands", {}).get("ignore_commands") or []:
            self._ajouter("command", e["command"], e.get("query_level", False),
                          e.get("reason", ""))
        hosts = f.get("hosts", {})
        for e in hosts.get("ignore_agent_names") or []:
            self._ajouter("agent_name", e["name"], e.get("query_level", False),
                          e.get("reason", ""))
        for e in hosts.get("ignore_agent_ids") or []:
            self._ajouter("agent_id", e["id"], e.get("query_level", False),
                          e.get("reason", ""))
        for c in f.get("composite") or []:
            if c.get("match_all"):
                self.composites.append(c)

    def clauses_must_not(self) -> list[dict]:
        """Clauses OpenSearch pour les entrées query_level: true."""
        return [{"term": {CHAMP[type_champ]: valeur}}
                for type_champ, valeur, _ in self.query_level
                if type_champ in CHAMP]

    def raison_suppression(self, src: dict) -> str | None:
        """Raison de suppression post-retrieval, ou None.

        Une alerte matchée query_level ne devrait pas arriver ici (le must_not
        l'a écartée), mais on la revérifie : si le filtre a été ajouté après
        coup, l'ancienne alerte déjà en base doit être suppressible au rejeu.
        """
        for type_champ, valeur, reason in self.post + self.query_level:
            chemin = CHAMP.get(type_champ)
            if chemin and str(_lire(src, chemin)) == valeur:
                return reason

        for c in self.composites:
            conditions = c["match_all"]
            # Toutes les clés doivent être connues ET matcher. Sans le premier
            # test, un composite aux clés inconnues donnerait un all() vide,
            # donc vrai, et supprimerait toutes les alertes.
            if conditions and all(k in CHAMP for k in conditions) and all(
                    str(_lire(src, CHAMP[k])) == str(v)
                    for k, v in conditions.items()):
                return c.get("name") or c.get("description") or "composite"
        return None


@lru_cache(maxsize=1)
def charger(chemin: str | None = None) -> NoiseFilter:
    p = Path(chemin) if chemin else CONFIG_DEFAUT
    with open(p, encoding="utf-8") as fh:
        return NoiseFilter(yaml.safe_load(fh) or {})
