"""Moteur UEBA — faire remonter les alertes LOW/MEDIUM qui le méritent.

Le pipeline n'ouvre un incident qu'à partir du niveau 12 (`MIN_LEVEL`). En
dessous, tout est ingéré mais rien ne graine : une intrusion qui n'émet que du
niveau 3-11 (énumération, exécution d'un binaire déposé, login depuis un pays
jamais vu, persistance discrète) est invisible. La monter en seuil brut noierait
le SOC et la facture LLM.

Ce module est le troisième étage de réduction, entre le noise filter et le
filtre VT d'un côté, et le LLM de l'autre :

    noise filter -> filtre VT -> **UEBA (0 token)** -> corrélation -> LLM

Il ne juge pas : il **classe**. Chaque alerte basse reçoit un score en BITS
d'information, les alertes voisines d'un même agent sont regroupées en
« signal », et seuls les signaux les mieux notés — dans la limite d'un BUDGET
explicite — sont promus en graine d'incident. À partir de là, le chemin est
celui de tout le monde : `correlate` -> `triage` (verdict VP/FP par le LLM) ->
case IRIS. Le LLM ne voit jamais une alerte basse isolée, il voit un incident
déjà constitué, déjà scoré, avec l'explication du score.

Trois primitives, toutes déterministes et explicables à un analyste (même
exigence que `correlate.py`) :

1. **Rareté (surprisal)** — `-log2(p)` de la valeur observée dans son scope.
   En bits : c'est ce qui rend les composantes SOMMABLES. Sommer des « points »
   n'a pas de sens, sommer des bits d'information si.
2. **Première vue (first-seen)** — la valeur n'existe pas dans un profil MÛR.
   Score plafond, MODULÉ par la rareté sur la flotte : un binaire inédit sur cet
   hôte mais présent sur 10 autres est un déploiement d'admin, pas une intrusion.
   C'est le principal anti-faux-positif du module.
3. **Chaîne MITRE** — plusieurs tactiques distinctes dans la fenêtre, pondérées
   (credential-access pèse plus que discovery) et bonifiées si elles progressent
   dans l'ordre de la kill chain.

Pas de ML non supervisé (isolation forest, autoencodeur) : sans jeu labellisé
on ne saurait pas mesurer sa dérive, et un score inexplicable ne peut ni être
contesté par un analyste ni justifier une remédiation. La surprisal donne le
même résultat et se lit en une phrase.

    python -m soc_agent.ueba --etat
    python -m soc_agent.ueba --simulation
"""

import argparse
import json
import math
import re
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg.rows import dict_row

from . import config

# --- Traits observés ---------------------------------------------------------
#
# Volontairement peu nombreux. Chacun doit répondre à « qu'est-ce que ça change
# au verdict que cette valeur soit inédite ? » ; un trait qui n'a pas de réponse
# n'apporte que du bruit et du coût.
#
# Le POIDS multiplie les bits du trait. `parent_child` pèse plus que `exe` : un
# `sh` seul est banal, un `nginx -> sh` est un webshell. `hour` pèse peu — un
# horaire inhabituel est un indice, jamais une preuve.
POIDS = {
    "exe":          1.0,   # binaire exécuté
    "fichier":      0.8,   # objet d'une alerte d'intégrité (FIM)
    "parent_child": 1.3,   # couple parent -> enfant (Windows/Sysmon)
    "srcip":        0.9,   # IP source de l'événement
    "pays":         1.0,   # pays GeoIP de l'IP source
    "dst_port":     0.7,   # port de destination (Suricata)
    "compte":       1.0,   # compte impliqué
    "rule_id":      0.5,   # règle qui a tiré
    "heure":        0.4,   # tranche horaire (ouvré / hors ouvré)
}

# Scopes : à quoi on rapporte la fréquence.
#   'host'      -> agent_id. Le comportement de la MACHINE.
#   'user@host' -> compte + agent_id. Le comportement de la PERSONNE sur cette
#                  machine — c'est là que vit la latéralisation (un compte
#                  légitime qui apparaît sur un hôte où il n'a jamais servi).
# On garde `agent_id` et pas `agent_name` : le nom peut changer, l'id non.

# Ordre canonique de la kill chain. Sert au bonus d'ordre : un même ENSEMBLE de
# tactiques vaut plus s'il PROGRESSE (accès -> exécution -> persistance ->
# credentials -> exfiltration) que s'il est observé en désordre.
ORDRE_TACTIQUES = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion",
    "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]

# Poids par tactique. Trois `Discovery` sont du bruit d'administration ;
# `Credential Access` + `Persistence` + `Exfiltration` sont une intrusion. Sans
# cette pondération, « 3 tactiques distinctes » remonte surtout des faux positifs.
POIDS_TACTIQUES = {
    "Reconnaissance": 1.0, "Resource Development": 1.0, "Initial Access": 3.0,
    "Execution": 2.0, "Persistence": 4.0, "Privilege Escalation": 4.0,
    "Defense Evasion": 3.0, "Credential Access": 5.0, "Discovery": 1.0,
    "Lateral Movement": 4.0, "Collection": 2.0, "Command and Control": 4.0,
    "Exfiltration": 5.0, "Impact": 5.0,
}

# Valeurs trop communes pour porter du signal, même inédites sur un hôte : les
# scorer ferait remonter le premier `bash` d'une machine fraîchement observée.
# Même logique que `correlate.ENTITES_GENERIQUES`, appliquée aux traits.
VALEURS_IGNOREES = {
    "/usr/bin/bash", "/bin/bash", "/usr/bin/sh", "/bin/sh", "/usr/bin/dash",
    "/bin/dash", "/usr/bin/zsh", "-", "", "unknown", "n/a", "none",
}

# Comptes qui ne désignent PAS une personne : comptes machine Active Directory
# (`WIN-DC$`, `WIN-DC$@LAB.LOCAL` — le `$` final est la convention AD) et
# pseudo-comptes du système d'exploitation. Ils authentifient en permanence,
# pour le compte de services, et leur volume écrase tout le reste.
#
# Mesuré en production : l'incident #2550 (case IRIS #193) comptait 4598
# alertes dont 3856 portées par `WIN-DC$`, soit 85 % d'ouvertures/fermetures de
# session du contrôleur de domaine. Le signal l'a promu, le LLM l'a raconté
# comme une compromission avérée, et `marquer_tp` a ensuite figé `WIN-DC$` à
# 12 bits À VIE — la boucle se refermait sur elle-même.
#
# Le scope `user@host` disparaît aussi pour ces comptes : profiler « le
# comportement de la personne WIN-DC$ » n'a pas de sens, et ce scope agrégerait
# tout le trafic de service de la machine sous une identité unique.
_RE_COMPTE_MACHINE = re.compile(r"\$(@|$)")
COMPTES_NON_PERSONNE = {
    "system", "système", "local system", "système local",
    "local service", "service local", "network service", "service réseau",
    "anonymous logon", "connexion anonyme", "nt authority\\system",
}

_WIN_SEP = re.compile(r"[\\/]+")


def _norm_compte(valeur) -> str | None:
    """Compte normalisé, ou None si ce n'est pas une identité de personne."""
    v = _norm(valeur)
    if v is None:
        return None
    if _RE_COMPTE_MACHINE.search(v) or v.lower() in COMPTES_NON_PERSONNE:
        return None
    return v


def _norm(valeur) -> str | None:
    """Valeur normalisée, ou None si elle ne porte rien d'exploitable."""
    if valeur is None:
        return None
    v = str(valeur).strip()
    if not v or v.lower() in VALEURS_IGNOREES:
        return None
    return v[:400]


def _raw(a: dict) -> dict:
    r = a.get("raw")
    if isinstance(r, dict):
        return r
    try:
        return json.loads(r) if r else {}
    except (TypeError, ValueError):
        return {}


def traits(a: dict) -> list[tuple[str, str, str, str]]:
    """(scope, scope_key, trait, valeur) observés dans une alerte.

    Rien ici n'est collecté en plus : tout sort de `alerts` et de `alerts.raw`,
    déjà en base. UEBA n'ajoute aucune ingestion, seulement une lecture.
    """
    raw = _raw(a)
    data = raw.get("data") or {}
    win = (data.get("win") or {}).get("eventdata") or {}
    audit = data.get("audit") or {}
    geo = raw.get("GeoLocation") or {}

    agent = str(a.get("agent_id") or "?")
    compte = _norm_compte(a.get("srcuser"))
    hote = ("host", agent)
    # Le scope utilisateur n'existe que si l'événement porte un compte. Sinon on
    # se rabat sur le seul scope machine : inventer un « inconnu@hôte » créerait
    # un profil fourre-tout où tout finirait par paraître normal.
    perso = ("user@host", f"{compte}@{agent}") if compte else None

    out: list[tuple[str, str, str, str]] = []

    def ajouter(trait: str, valeur, sur_perso: bool = True) -> None:
        v = _norm(valeur)
        if v is None:
            return
        out.append((hote[0], hote[1], trait, v))
        if perso and sur_perso:
            out.append((perso[0], perso[1], trait, v))

    # Binaire exécuté. UNIQUEMENT auditd et Sysmon — surtout pas le repli
    # `entity`, qui vaut `syscheck.path` pour les alertes FIM : sur Windows
    # c'est une clé de registre `HKEY_...`, sur Proxmox une archive LVM
    # `pve_19796-1149630808.vg`. Ni l'un ni l'autre n'est un exécutable, et le
    # second est unique par construction — donc « jamais vu » à chaque
    # occurrence. Mesuré en recette : score 1434 sur l'hôte Proxmox, uniquement
    # composé d'archives LVM.
    ajouter("exe", audit.get("exe") or win.get("image"))

    # Objet touché par une alerte d'intégrité (fichier déposé, clé modifiée).
    # Trait séparé et moins pesant que `exe` : un fichier qui apparaît est un
    # indice, un binaire qui s'exécute est un fait. Le garde-fou de cardinalité
    # ci-dessous neutralise les chemins horodatés/rotatifs.
    ajouter("fichier", a.get("entity"))

    # Couple parent -> enfant. Uniquement Windows/Sysmon : auditd ne donne pas
    # le nom du parent, seulement son pid, qu'on ne peut pas résoudre après coup.
    parent, enfant = win.get("parentImage"), win.get("image")
    if parent and enfant:
        ajouter("parent_child",
                f"{_WIN_SEP.split(parent)[-1]}>{_WIN_SEP.split(enfant)[-1]}")

    ajouter("srcip", a.get("srcip"))
    ajouter("pays", geo.get("country_name"))
    ajouter("dst_port", data.get("dstport"))
    # Le compte est un trait DU SCOPE MACHINE seulement : sur le scope
    # `user@host`, il est déjà dans la clé, l'observer serait tautologique.
    ajouter("compte", compte, sur_perso=False)
    ajouter("rule_id", a.get("rule_id"))

    ts = a.get("ts")
    if isinstance(ts, datetime):
        # Tranche grossière et non l'heure exacte : 24 valeurs par profil
        # demandent des mois pour être mûres, 4 suffisent à distinguer
        # « 3 h du matin un dimanche » de l'activité de bureau.
        ouvre = ts.weekday() < 5 and 7 <= ts.hour < 20
        ajouter("heure", "ouvre" if ouvre else "hors_ouvre")

    return out


# --- Scoring -----------------------------------------------------------------

def surprisal(compte: int, total: int, distincts: int) -> float:
    """Information portée par une valeur vue `compte` fois sur `total`, en bits.

    Lissage de Laplace (alpha=0.5) : sans lui, une valeur jamais vue donne une
    probabilité nulle, donc des bits infinis. Le lissage borne aussi le score
    d'un profil encore maigre, ce qui est exactement ce qu'on veut — peu
    d'observations, peu de confiance.
    """
    alpha = 0.5
    denom = total + alpha * max(distincts, 1)
    if denom <= 0:
        return 0.0
    p = (compte + alpha) / denom
    return max(0.0, -math.log2(min(p, 1.0)))


def cardinalite_exploitable(stats: dict | None) -> bool:
    """Le trait porte-t-il une information, ou change-t-il de valeur à chaque fois ?

    Un trait dont presque chaque observation est une valeur neuve (chemins
    horodatés, archives rotatives, GUID, identifiants de session) est inédit par
    construction : « jamais vu » n'y signifie rien. Sans ce garde-fou, ces
    traits saturent le score en permanence et écrasent tout le reste.

    On juge sur le RATIO valeurs distinctes / observations, pas sur une liste de
    motifs : aucune liste noire ne peut anticiper ce qu'un parc produit, alors
    que la statistique se corrige seule quand le comportement change.
    """
    if not stats or stats.get("total", 0) < config.UEBA_CARDINALITE_MIN_OBS:
        return True   # trop peu d'observations pour conclure : on n'exclut pas
    return (stats["distincts"] / stats["total"]) <= config.UEBA_CARDINALITE_MAX


def _bits_trait(profil: dict | None, stats: dict | None, flotte: int,
                mature: bool) -> tuple[float, str]:
    """Bits d'un trait + la phrase qui l'explique. (0.0, "") si non scorable."""
    if profil is not None and profil.get("seen_in_tp"):
        # Trait déjà impliqué dans un vrai positif : il ne peut PAS devenir une
        # habitude, quelle que soit sa fréquence. Sinon un attaquant patient
        # normalise son propre outillage en le lançant tous les jours.
        return config.UEBA_FIRSTSEEN_BITS, "déjà vu dans un vrai positif"

    if not cardinalite_exploitable(stats):
        # Le trait est unique PAR CONSTRUCTION sur ce scope : presque chaque
        # observation apporte une valeur neuve (chemins horodatés, archives
        # rotatives, identifiants de session, GUID). « Jamais vu » n'y veut donc
        # rien dire, et la surprisal y est maximale en permanence. Mesuré en
        # recette : les archives LVM de l'hôte Proxmox donnaient à elles seules
        # un score de 1434, quarante fois le plancher.
        #
        # Garde-fou GÉNÉRAL et non liste noire : on ne peut pas énumérer à
        # l'avance tout ce qu'un parc produit de haute cardinalité, et une liste
        # noire vieillit mal. La statistique, elle, se corrige seule.
        return 0.0, ""

    if not mature:
        # Profil trop jeune : TOUT y est inédit. Scorer maintenant enverrait
        # l'intégralité du parc au LLM le premier jour. On observe, on ne juge
        # pas encore — même philosophie que le mode training.
        return 0.0, ""

    if profil is None:
        # Première vue. Modulée par la flotte : inédit ici mais banal ailleurs
        # = déploiement/administration, pas intrusion.
        bits = config.UEBA_FIRSTSEEN_BITS
        if flotte >= config.UEBA_FLOTTE_BANAL:
            bits *= 0.2
            note = f"inédit ici mais présent sur {flotte} hôtes"
        elif flotte >= 1:
            bits *= 0.6
            note = f"inédit ici, vu sur {flotte} autre(s) hôte(s)"
        else:
            note = "jamais vu ici ni ailleurs sur la flotte"
        return bits, note

    if stats is None:
        return 0.0, ""

    if profil["days_seen"] >= config.UEBA_JOURS_HABITUEL:
        # Vu sur assez de jours DISTINCTS pour être une habitude. Le nombre
        # d'occurrences ne suffit pas : 500 exécutions en un seul jour est un
        # incident, pas une baseline.
        return 0.0, ""

    bits = surprisal(profil["total"], stats["total"], stats["distincts"])
    if bits < config.UEBA_BITS_MIN_RARETE:
        return 0.0, ""
    return bits, (f"rare : {profil['total']}x sur {stats['total']} "
                  f"observations, {profil['days_seen']} jour(s)")


class _Etat:
    """Profils + statistiques de scope chargés en mémoire pour un lot.

    On score CHAQUE alerte contre l'état d'AVANT elle, puis on l'absorbe.
    L'ordre est capital : absorber d'abord ferait disparaître tout first-seen
    (la valeur serait déjà connue au moment de la scorer). C'est aussi ce qui
    fait que la deuxième occurrence d'une même valeur dans un même lot ne
    rapporte plus le score plein.
    """

    def __init__(self, profils: dict, stats: dict, flotte: dict, maturite: dict):
        self.profils = profils      # (scope, key, trait, valeur) -> {...}
        self.stats = stats          # (scope, key, trait) -> {total, distincts}
        self.flotte = flotte        # (trait, valeur) -> nb d'hôtes distincts
        self.maturite = maturite    # (scope, key, trait) -> bool
        self.touches: set[tuple] = set()
        self.obs: dict[tuple, int] = {}   # (scope,key,trait,valeur,jour) -> n

    def mature(self, scope: str, key: str, trait: str) -> bool:
        return self.maturite.get((scope, key, trait), False)

    def absorber(self, scope: str, key: str, trait: str, valeur: str,
                 ts: datetime) -> None:
        cle = (scope, key, trait, valeur)
        p = self.profils.get(cle)
        jour = ts.date()
        if p is None:
            self.profils[cle] = {"total": 1, "days_seen": 1,
                                 "first_seen": ts, "last_seen": ts,
                                 "jours": {jour}, "seen_in_tp": False}
            self.flotte[(trait, valeur)] = self.flotte.get((trait, valeur), 0) + (
                1 if scope == "host" else 0)
        else:
            p["total"] += 1
            p["last_seen"] = max(p.get("last_seen") or ts, ts)
            jours = p.setdefault("jours", set())
            if jour not in jours:
                jours.add(jour)
                p["days_seen"] = p.get("days_seen", 0) + 1
        s = self.stats.setdefault((scope, key, trait),
                                  {"total": 0, "distincts": 0,
                                   "premiere_obs": ts})
        s["total"] += 1
        if p is None:
            s["distincts"] += 1
        self.touches.add(cle)
        self.obs[(scope, key, trait, valeur, jour)] = (
            self.obs.get((scope, key, trait, valeur, jour), 0) + 1)


SELECT_A_OBSERVER = """
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, rule_groups,
       mitre_tactics, srcip, srcuser, entity, raw
  FROM alerts
 WHERE NOT ueba_vu AND NOT suppressed
 ORDER BY ts, id
 LIMIT %s
"""


def _charger_etat(conn, cles: set[tuple]) -> _Etat:
    """Un aller-retour par table, jamais une requête par alerte."""
    profils: dict[tuple, dict] = {}
    stats: dict[tuple, dict] = {}
    flotte: dict[tuple, int] = {}
    maturite: dict[tuple, bool] = {}
    if not cles:
        return _Etat(profils, stats, flotte, maturite)

    # Listes matérialisées : les quatre colonnes passées à `unnest` doivent être
    # alignées ligne à ligne. Itérer un `set` quatre fois donnerait le même
    # ordre en pratique, mais rien ne le garantit — on fige.
    cles_l = sorted(cles)
    scopes = sorted({(s, k, t) for s, k, t, _ in cles})
    valeurs = sorted({(t, v) for _, _, t, v in cles})

    lignes = conn.execute(
        "SELECT scope, scope_key, trait, valeur, total, days_seen, first_seen,"
        "       last_seen, seen_in_tp FROM ueba_profiles "
        " WHERE (scope, scope_key, trait, valeur) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[], %s::text[], %s::text[]))",
        ([c[0] for c in cles_l], [c[1] for c in cles_l],
         [c[2] for c in cles_l], [c[3] for c in cles_l])).fetchall()
    for l in lignes:
        profils[(l["scope"], l["scope_key"], l["trait"], l["valeur"])] = dict(l)

    lignes = conn.execute(
        "SELECT scope, scope_key, trait, total, distincts, premiere_obs "
        "  FROM ueba_scopes WHERE (scope, scope_key, trait) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[], %s::text[]))",
        ([s[0] for s in scopes], [s[1] for s in scopes],
         [s[2] for s in scopes])).fetchall()
    seuil = datetime.now(timezone.utc) - timedelta(days=config.UEBA_MATURITE_JOURS)
    for l in lignes:
        cle = (l["scope"], l["scope_key"], l["trait"])
        stats[cle] = dict(l)
        maturite[cle] = (l["premiere_obs"] is not None
                         and l["premiere_obs"] <= seuil
                         and l["total"] >= config.UEBA_MATURITE_MIN_OBS)

    # Rareté sur la flotte : sur combien d'HÔTES distincts cette valeur est-elle
    # connue ? Uniquement le scope 'host' — compter les scopes utilisateur
    # gonflerait le chiffre sans rien dire de la diffusion réelle.
    lignes = conn.execute(
        "SELECT trait, valeur, count(DISTINCT scope_key) AS n "
        "  FROM ueba_profiles WHERE scope = 'host' AND (trait, valeur) IN "
        "       (SELECT * FROM unnest(%s::text[], %s::text[])) "
        " GROUP BY trait, valeur",
        ([v[0] for v in valeurs], [v[1] for v in valeurs])).fetchall()
    for l in lignes:
        flotte[(l["trait"], l["valeur"])] = l["n"]

    return _Etat(profils, stats, flotte, maturite)


def observer(limite: int | None = None) -> tuple[int, int]:
    """Score les alertes non encore vues, puis les absorbe dans la baseline.

    Retourne (alertes observées, alertes ayant un score non nul).
    """
    limite = limite or config.UEBA_LOT
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alertes = conn.execute(SELECT_A_OBSERVER, (limite,)).fetchall()
        if not alertes:
            return 0, 0

        par_alerte = {a["id"]: traits(a) for a in alertes}
        cles = {t for ts_ in par_alerte.values() for t in ts_}
        etat = _charger_etat(conn, cles)

        n_scorees = 0
        for a in alertes:
            total_bits = 0.0
            details: list[dict] = []
            for scope, key, trait, valeur in par_alerte[a["id"]]:
                bits, note = _bits_trait(
                    etat.profils.get((scope, key, trait, valeur)),
                    etat.stats.get((scope, key, trait)),
                    etat.flotte.get((trait, valeur), 0),
                    etat.mature(scope, key, trait))
                if bits > 0:
                    pondere = min(bits * POIDS.get(trait, 1.0),
                                  config.UEBA_CAP_TRAIT)
                    total_bits += pondere
                    details.append({"trait": trait, "valeur": valeur,
                                    "scope": scope, "bits": round(pondere, 2),
                                    "note": note})
                # Absorption APRÈS le score, y compris quand il est nul.
                etat.absorber(scope, key, trait, valeur, a["ts"])

            total_bits = min(total_bits, config.UEBA_CAP_ALERTE)
            details.sort(key=lambda d: -d["bits"])
            if total_bits > 0:
                n_scorees += 1
            conn.execute(
                "UPDATE alerts SET ueba_vu = true, ueba_score = %s, "
                "ueba_traits = %s WHERE id = %s",
                (round(total_bits, 2),
                 json.dumps(details[:6], ensure_ascii=False, default=str),
                 a["id"]))

        _persister(conn, etat)
        conn.commit()
    return len(alertes), n_scorees


def _persister(conn, etat: _Etat) -> None:
    """Écrit observations, profils et statistiques de scope.

    `days_seen` est RECALCULÉ depuis `ueba_observations` et non incrémenté à
    l'aveugle : rejouer un lot ne doit pas gonfler le nombre de jours distincts,
    sans quoi une valeur rejouée passerait pour une habitude.
    """
    for (scope, key, trait, valeur, jour), n in etat.obs.items():
        conn.execute(
            "INSERT INTO ueba_observations (scope, scope_key, trait, valeur, "
            "jour, nb) VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (scope, scope_key, trait, valeur, jour) DO UPDATE "
            "SET nb = ueba_observations.nb + EXCLUDED.nb",
            (scope, key, trait, valeur, jour, n))

    for cle in etat.touches:
        scope, key, trait, valeur = cle
        conn.execute(
            "INSERT INTO ueba_profiles (scope, scope_key, trait, valeur, total,"
            " days_seen, first_seen, last_seen) "
            "SELECT %s, %s, %s, %s, sum(nb), count(*), min(jour), max(jour) "
            "  FROM ueba_observations "
            " WHERE scope=%s AND scope_key=%s AND trait=%s AND valeur=%s "
            "ON CONFLICT (scope, scope_key, trait, valeur) DO UPDATE "
            "   SET total = EXCLUDED.total, days_seen = EXCLUDED.days_seen, "
            "       first_seen = EXCLUDED.first_seen, "
            "       last_seen = GREATEST(ueba_profiles.last_seen, "
            "                            EXCLUDED.last_seen)",
            (scope, key, trait, valeur, scope, key, trait, valeur))

    for (scope, key, trait) in {(c[0], c[1], c[2]) for c in etat.touches}:
        conn.execute(
            "INSERT INTO ueba_scopes (scope, scope_key, trait, total, distincts,"
            " premiere_obs, derniere_obs) "
            "SELECT %s, %s, %s, coalesce(sum(total),0), count(*), "
            "       min(first_seen), max(last_seen) FROM ueba_profiles "
            " WHERE scope=%s AND scope_key=%s AND trait=%s "
            "ON CONFLICT (scope, scope_key, trait) DO UPDATE "
            "   SET total = EXCLUDED.total, distincts = EXCLUDED.distincts, "
            "       premiere_obs = EXCLUDED.premiere_obs, "
            "       derniere_obs = EXCLUDED.derniere_obs",
            (scope, key, trait, scope, key, trait))


# --- Signaux : regroupement et chaîne MITRE ----------------------------------

# `ueba_signal_id IS NULL` et non `NOT ueba_seed` : une alerte qui a DÉJÀ
# appartenu à un signal est consommée, définitivement. `ueba_seed` dit
# « corrélable comme graine » et `correlate` peut le remettre à false quand il
# écarte le groupe (score sous le plancher) ; s'en servir ici comme filtre
# rendrait ces alertes à nouveau candidates, et le budget quotidien tournerait
# en rond sur le même bruit à chaque cycle.
SELECT_CANDIDATES = """
SELECT id, ts, agent_id, agent_name, rule_id, rule_level, mitre_tactics,
       srcuser, ueba_score, ueba_traits
  FROM alerts
 WHERE ueba_vu AND NOT suppressed AND ueba_signal_id IS NULL
   AND incident_id IS NULL
   AND ueba_score > 0
   AND rule_level < %s
   AND ts >= now() - make_interval(hours => %s)
 ORDER BY agent_id, ts, id
"""


def bonus_chaine(tactiques_ordonnees: list[str]) -> tuple[float, str | None]:
    """Bonus lié à la diversité ET à la progression des tactiques MITRE.

    Le simple « 3 techniques de 3 tactiques » remonte surtout `Discovery` x3,
    soit un admin qui inventorie sa machine. D'où deux corrections :
      - chaque tactique DISTINCTE apporte son poids (credential-access = 5,
        discovery = 1) ;
      - un bonus s'ajoute si les tactiques progressent dans l'ordre de la kill
        chain — c'est le signal le plus fort qu'on puisse tirer sans LLM.
    """
    distinctes = []
    for t in tactiques_ordonnees:
        if t not in distinctes:
            distinctes.append(t)
    if len(distinctes) < config.UEBA_MIN_TACTIQUES:
        return 0.0, None

    bonus = sum(POIDS_TACTIQUES.get(t, 1.0) for t in distinctes)

    # Plus longue sous-suite croissante dans l'ordre canonique : mesure de
    # progression, insensible aux tactiques hors chaîne.
    rangs = [ORDRE_TACTIQUES.index(t) for t in tactiques_ordonnees
             if t in ORDRE_TACTIQUES]
    meilleure = 0
    longueurs: list[int] = []
    for i, r in enumerate(rangs):
        longueurs.append(1 + max([longueurs[j] for j in range(i)
                                  if rangs[j] < r] or [0]))
        meilleure = max(meilleure, longueurs[-1])
    progression = ""
    if meilleure >= config.UEBA_MIN_TACTIQUES:
        bonus += config.UEBA_BONUS_ORDRE * (meilleure - config.UEBA_MIN_TACTIQUES + 1)
        progression = f", progression kill-chain sur {meilleure} étapes"

    return bonus, (f"{len(distinctes)} tactiques MITRE distinctes "
                   f"({', '.join(distinctes)}){progression}")


def _grouper_signaux(alertes: list[dict]) -> list[list[dict]]:
    """Chaîne les alertes d'un même agent séparées de moins de la fenêtre.

    Même esprit que `correlate._grouper`, en beaucoup plus simple : ici on ne
    cherche pas un point commun nommable (les alertes basses n'en partagent
    souvent aucun), on cherche une CONCENTRATION anormale dans le temps sur une
    machine. Le point commun, c'est la machine et la fenêtre.
    """
    ecart = timedelta(minutes=config.UEBA_FENETRE_MINUTES)
    duree_max = timedelta(hours=config.UEBA_SIGNAL_MAX_HEURES)
    groupes: list[list[dict]] = []
    courant: list[dict] = []
    for a in alertes:
        # Chaînage de proche en proche : une intrusion discrète est LENTE, et
        # c'est bien elle qu'on cherche. Mais sans plafond de durée, un hôte
        # bavard qui émet une alerte toutes les 50 minutes agglomère sa journée
        # entière en un seul signal — le score enfle par accumulation et non par
        # anomalie, et le prompt part avec des heures de bruit.
        if (courant and a["agent_id"] == courant[-1]["agent_id"]
                and a["ts"] - courant[-1]["ts"] <= ecart
                and a["ts"] - courant[0]["ts"] <= duree_max):
            courant.append(a)
        else:
            if courant:
                groupes.append(courant)
            courant = [a]
    if courant:
        groupes.append(courant)
    return groupes


def scorer_groupe(groupe: list[dict]) -> tuple[float, list[dict]]:
    """Score d'un groupe + les motifs qui le composent.

    Somme plafonnée PAR TRAIT et non brute : quarante exécutions du même binaire
    rare ne valent pas quarante fois le score, sinon une tâche planifiée rare
    écrase tout le reste. On garde le meilleur de chaque trait, plus une part
    décroissante des répétitions.
    """
    meilleur_par_trait: dict[str, dict] = {}
    for a in groupe:
        for d in (a.get("ueba_traits") or []):
            cle = f"{d['trait']}:{d['valeur']}"
            garde = meilleur_par_trait.get(cle)
            if garde is None or d["bits"] > garde["bits"]:
                meilleur_par_trait[cle] = dict(d)

    motifs = sorted(meilleur_par_trait.values(), key=lambda d: -d["bits"])
    score = sum(min(d["bits"], config.UEBA_CAP_TRAIT) for d in motifs)

    tactiques = [t for a in groupe for t in (a.get("mitre_tactics") or [])]
    bonus, phrase = bonus_chaine(tactiques)
    if bonus:
        score += bonus
        motifs.append({"trait": "chaine_mitre", "valeur": "", "scope": "host",
                       "bits": round(bonus, 2), "note": phrase})

    return score, motifs[:8]


def _budget_restant(conn) -> int:
    """Places de promotion restantes sur les 24 dernières heures.

    Le seuil de score ne suffit pas à borner la facture : le volume d'alertes
    varie d'un facteur dix entre une journée calme et une campagne. Le budget,
    lui, est un nombre qu'on décide. Un signal non promu n'est pas perdu — il
    est réévalué au cycle suivant, et son score aura grossi s'il continue.
    """
    n = conn.execute(
        "SELECT count(*) AS n FROM ueba_signals "
        " WHERE statut = 'promu' AND created_at >= now() - interval '24 hours'"
    ).fetchone()["n"]
    return max(0, config.UEBA_BUDGET_JOUR - n)


def evaluer(simulation: bool = False) -> list[dict]:
    """Regroupe, score, et promeut les meilleurs signaux dans la limite du budget.

    Retourne la liste des signaux promus.
    """
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alertes = conn.execute(
            SELECT_CANDIDATES,
            (config.MIN_LEVEL, config.UEBA_RETENTION_HOURS)).fetchall()
        if not alertes:
            return []

        signaux = []
        for groupe in _grouper_signaux(alertes):
            score, motifs = scorer_groupe(groupe)
            signaux.append({
                "agent_id": groupe[0]["agent_id"],
                "agent_name": groupe[0]["agent_name"],
                "debut": groupe[0]["ts"], "fin": groupe[-1]["ts"],
                "score": round(score, 2), "motifs": motifs,
                "alert_ids": [a["id"] for a in groupe],
            })
        signaux.sort(key=lambda s: -s["score"])

        # Les signaux non promus sont recalculés à chaque passage : on efface
        # les « en attente » du tour précédent plutôt que de les mettre à jour,
        # leur périmètre ayant pu changer (alertes nouvellement rattachées).
        conn.execute("DELETE FROM ueba_signals WHERE statut = 'en_attente'")

        budget = min(_budget_restant(conn), config.UEBA_BUDGET_PAR_CYCLE)
        promus: list[dict] = []
        for s in signaux:
            eligible = (s["score"] >= config.UEBA_SCORE_PLANCHER
                        and len(promus) < budget and not simulation)
            statut = "promu" if eligible else "en_attente"
            sid = conn.execute(
                "INSERT INTO ueba_signals (agent_id, agent_name, debut, fin, "
                " score, motifs, alert_ids, statut) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",
                (s["agent_id"], s["agent_name"], s["debut"], s["fin"],
                 s["score"], json.dumps(s["motifs"], ensure_ascii=False,
                                        default=str),
                 s["alert_ids"], statut)).fetchone()["id"]
            if eligible:
                # La promotion ne fabrique pas d'incident : elle rend les
                # alertes GRAINABLES. C'est `correlate` qui décide ensuite du
                # découpage, avec ses propres règles — une seule logique de
                # regroupement dans le projet.
                conn.execute(
                    "UPDATE alerts SET ueba_seed = true, ueba_signal_id = %s "
                    " WHERE id = ANY(%s)", (sid, s["alert_ids"]))
                s["id"] = sid
                promus.append(s)
        conn.commit()
    return promus


def marquer_tp(incident_id: int) -> int:
    """Interdit à la baseline d'absorber les traits d'un vrai positif.

    Sans ça, un attaquant patient normalise son propre outillage : il suffit de
    le lancer tous les jours pour qu'il devienne « habituel » et cesse d'être
    scoré. Même garde-fou que la whitelist automatique, qui refuse toute
    signature déjà vue dans un vrai positif.
    """
    n = 0
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        alertes = conn.execute(
            "SELECT id, ts, agent_id, agent_name, rule_id, srcip, srcuser, "
            "       entity, raw FROM alerts WHERE incident_id = %s",
            (incident_id,)).fetchall()
        cles = {t for a in alertes for t in traits(a)}
        for scope, key, trait, valeur in cles:
            n += conn.execute(
                "UPDATE ueba_profiles SET seen_in_tp = true "
                " WHERE scope=%s AND scope_key=%s AND trait=%s AND valeur=%s "
                "   AND NOT seen_in_tp",
                (scope, key, trait, valeur)).rowcount
        conn.commit()
    return n


def purger() -> int:
    """Fait vieillir la baseline.

    Un profil qui ne vieillit jamais fige le comportement d'il y a six mois : un
    serveur réinstallé resterait « normal » sur ses anciens binaires, et un
    poste dont l'usage a changé produirait du bruit sans fin. On supprime les
    observations au-delà de la fenêtre, puis on RECALCULE les profils depuis ce
    qui reste — jamais de décrément à l'aveugle.
    """
    with psycopg.connect(config.PG_DSN) as conn:
        n = conn.execute(
            "DELETE FROM ueba_observations WHERE jour < current_date - %s",
            (config.UEBA_MEMOIRE_JOURS,)).rowcount
        if n:
            conn.execute("""
                UPDATE ueba_profiles p
                   SET total = a.total, days_seen = a.jours,
                       first_seen = a.debut, last_seen = a.fin
                  FROM (SELECT scope, scope_key, trait, valeur, sum(nb) total,
                               count(*) jours, min(jour) debut, max(jour) fin
                          FROM ueba_observations
                         GROUP BY 1,2,3,4) a
                 WHERE p.scope=a.scope AND p.scope_key=a.scope_key
                   AND p.trait=a.trait AND p.valeur=a.valeur""")
            # Profils dont plus aucune observation ne subsiste. `seen_in_tp` est
            # préservé : un trait vu dans un vrai positif ne doit jamais
            # redevenir vierge par simple péremption.
            conn.execute(
                "DELETE FROM ueba_profiles p WHERE NOT p.seen_in_tp AND NOT EXISTS "
                "(SELECT 1 FROM ueba_observations o WHERE o.scope=p.scope "
                " AND o.scope_key=p.scope_key AND o.trait=p.trait "
                " AND o.valeur=p.valeur)")
        conn.commit()
    return n


def tourner() -> tuple[int, int, list[dict]]:
    """Un passage complet : observation, scoring, promotion. Appelé par cycle.py."""
    if not config.UEBA_ENABLED:
        return 0, 0, []
    vues, scorees = observer()
    promus = evaluer()
    # Vieillissement de la baseline. Appelé à chaque passage plutôt que par un
    # job dédié : le DELETE est indexé sur `jour` et ne rend rien la plupart du
    # temps ; le recalcul des profils n'a lieu que s'il a effectivement purgé.
    purger()
    return vues, scorees, promus


# --- CLI ---------------------------------------------------------------------

def etat() -> None:
    with psycopg.connect(config.PG_DSN, row_factory=dict_row) as conn:
        r = conn.execute(
            "SELECT count(*) AS profils, count(DISTINCT scope_key) AS scopes, "
            "       coalesce(sum(total),0) AS obs FROM ueba_profiles").fetchone()
        print(f"profils : {r['profils']} ({r['scopes']} scopes, "
              f"{r['obs']} observations)")
        murs = conn.execute(
            "SELECT count(*) AS n FROM ueba_scopes "
            " WHERE premiere_obs <= now() - make_interval(days => %s) "
            "   AND total >= %s",
            (config.UEBA_MATURITE_JOURS, config.UEBA_MATURITE_MIN_OBS)
        ).fetchone()["n"]
        total_scopes = conn.execute(
            "SELECT count(*) AS n FROM ueba_scopes").fetchone()["n"]
        print(f"scopes mûrs : {murs}/{total_scopes} "
              f"(>= {config.UEBA_MATURITE_JOURS} j et "
              f"{config.UEBA_MATURITE_MIN_OBS} observations)")
        reste = conn.execute(
            "SELECT count(*) AS n FROM alerts WHERE NOT ueba_vu AND NOT suppressed"
        ).fetchone()["n"]
        print(f"alertes à observer : {reste}")
        print(f"budget : {_budget_restant(conn)}/{config.UEBA_BUDGET_JOUR} "
              "promotions restantes sur 24 h")
        for s in conn.execute(
                "SELECT id, agent_name, score, statut, debut, motifs "
                "  FROM ueba_signals ORDER BY created_at DESC LIMIT 15"):
            phrases = "; ".join(
                f"{m['trait']}={m['valeur']} +{m['bits']}" for m in
                (s["motifs"] or [])[:3])
            print(f"  #{s['id']:<5} {s['statut']:<11} {s['score']:6.1f} "
                  f"{str(s['agent_name'] or '?'):<14} {s['debut']:%m-%d %H:%M}"
                  f"  {phrases}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--etat", action="store_true",
                    help="maturité des profils, budget, derniers signaux")
    ap.add_argument("--simulation", action="store_true",
                    help="score et enregistre les signaux SANS rien promouvoir "
                         "(calibrage du plancher, zéro token consommé)")
    ap.add_argument("--purger", action="store_true",
                    help="fait vieillir la baseline (UEBA_MEMOIRE_JOURS)")
    args = ap.parse_args()

    if args.etat:
        etat()
        return
    if args.purger:
        print(f"{purger()} observation(s) périmée(s) supprimée(s).")
        return

    vues, scorees, _ = (0, 0, [])
    vues, scorees = observer()
    print(f"observation : {vues} alertes, {scorees} avec un score non nul")
    promus = evaluer(simulation=args.simulation)
    if args.simulation:
        print("simulation : aucun signal promu.")
    for s in promus:
        print(f"  signal #{s['id']} {s['agent_name']} score {s['score']} "
              f"-> {len(s['alert_ids'])} alertes graine")
    if not promus and not args.simulation:
        print("aucun signal au-dessus du plancher (ou budget épuisé).")


if __name__ == "__main__":
    main()
