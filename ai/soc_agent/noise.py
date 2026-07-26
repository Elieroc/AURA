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

# Le fichier concerné n'a pas un emplacement unique : selon le décodeur, c'est
# syscheck.path, le fichier VirusTotal, la cible auditd… « file » est donc un
# champ VIRTUEL, résolu par essais successifs. Réservé aux composites
# (post-retrieval) : il permet de whitelister un chemin précis sans aveugler
# toute une règle — p.ex. /tmp/eicar.com sans neutraliser la règle VirusTotal.
FICHIER_CHEMINS = [
    "syscheck.path",
    "data.virustotal.source.file",
    "data.audit.exe",
    "data.audit.file.name",
    "data.win.eventdata.image",
]

# Champs autorisés dans un match_all de composite (simples + le virtuel).
CHAMP_COMPOSITE = set(CHAMP) | {"file"}


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


def _valeur_champ(src: dict, champ: str):
    """Valeur d'un champ de composite, y compris le virtuel « file »."""
    if champ == "file":
        for chemin in FICHIER_CHEMINS:
            v = _lire(src, chemin)
            if v:
                return v
        return None
    return _lire(src, CHAMP.get(champ, champ))


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

    def ajouter_composite(self, match_all: dict, nom: str) -> None:
        """Ajoute une règle composite (utilisé pour les exceptions en base).

        Toujours post-retrieval : une exception large doit rester rattrapable,
        donc jamais écartée côté indexer.
        """
        self.composites.append({"name": nom, "match_all": match_all})

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
            if conditions and all(k in CHAMP_COMPOSITE for k in conditions) and all(
                    str(_valeur_champ(src, k)) == str(v)
                    for k, v in conditions.items()):
                return c.get("name") or c.get("description") or "composite"
        return None


def charger_avec_db(conn, chemin: str | None = None) -> NoiseFilter:
    """Filtre complet : noise_filter.yaml (humain) + whitelist_rules (auto).

    Reconstruit à chaque appel, sans cache : les exceptions auto évoluent à
    chaque cycle. À appeler une fois par run et passer aux fonctions, pas par
    alerte.
    """
    p = Path(chemin) if chemin else CONFIG_DEFAUT
    with open(p, encoding="utf-8") as fh:
        filtre = NoiseFilter(yaml.safe_load(fh) or {})

    # Curseur tuple explicite : si la connexion appelante utilise dict_row,
    # déballer « for sig, match_all, reason in ... » itérerait les CLÉS de
    # chaque ligne, pas ses valeurs, et chargerait des composites cassés.
    from psycopg.rows import tuple_row
    with conn.cursor(row_factory=tuple_row) as cur:
        cur.execute("SELECT signature, match_all, reason FROM whitelist_rules "
                    "WHERE active")
        for sig, match_all, reason in cur.fetchall():
            filtre.ajouter_composite(match_all, reason or sig)
    return filtre
