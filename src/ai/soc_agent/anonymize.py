"""Pseudonymisation réversible avant envoi au LLM cloud (DeepSeek).

Les données SOC quittent l'hôte : on doit protéger la confidentialité du
CLIENT sans détruire le signal du triage. Constat de fond (visible dans
render.py) : **ce qui décide le verdict, ce sont les attributs, pas les
identifiants.** Une IP notée 98/100, RU, 2100 signalements, une extension
`.lockbit`, un chemin `/root`, une auth réussie — aucun de ces signaux n'a
besoin de la valeur littérale de l'IP, du hostname ou du compte.

Principe : séparer l'IDENTIFIANT (PII/actif client, ne sort jamais) de
l'ATTRIBUT (le signal analytique, non identifiant → sort verbatim).

- Actifs internes (hostname, comptes nommés, IP privées, chemins) → jeton
  stable `<HOTE_1>`, `<COMPTE_1>`, `<IP_1>`, `<FICHIER_1>`, cohérent dans
  l'incident pour préserver les chaînes de raisonnement du modèle.
- IOC externes (IP publique attaquant, hash malware) → gardés en clair : ce
  n'est pas de la PII client, c'est de la threat intel déjà connue de VT /
  AbuseIPDB. Choix produit assumé.
- Attributs (score, pays, positifs, extension, catégorie de chemin) → gardés.

La correspondance jeton→valeur reste en Postgres loopback (mêmes données que
`alerts.raw`, même localité — zéro nouvelle exposition) et sert à réhydrater
la réponse du LLM : l'analyste voit les vraies valeurs dans IRIS, seul DeepSeek
a vu les jetons.

Ce module réduit fortement l'identifiabilité ; il ne la annule pas. Garde-fou
fail-closed : `verifier_fuite` refuse l'envoi si un identifiant interne connu,
un e-mail ou une IP privée subsiste dans le texte final.
"""

import copy
import ipaddress
import re

# Comptes génériques : rôles, pas des personnes. On les GARDE — « root » ou
# « administrator » porte le signal de privilège, et n'identifie personne.
GENERIC_ACCOUNTS = {"root", "administrator", "admin", "system", "guest",
                      "-", "n/a", "none", "localsystem", "networkservice"}

# Traits UEBA dont la valeur est un ATTRIBUT et non un identifiant : elle porte
# le signal analytique (« pays inhabituel », « port inhabituel ») sans désigner
# un actif client, et sort donc verbatim. Tout trait absent de cette liste est
# pseudonymisé — y compris un trait ajouté plus tard dans ueba.py (cf. la
# branche par défaut dans `anonymiser`).
UEBA_TRAIT_ATTRIBUTES = {"pays", "heure", "dst_port", "rule_id", "chaine_mitre"}

_HASH = re.compile(r"^[A-Fa-f0-9]{32,64}$")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
# Chemins dans le texte libre. Unix : au moins deux segments (« /a/b ») pour ne
# pas confondre avec « 15/15 ». Les jetons `<FICHIER_1>` ne matchent pas (le
# « < » n'est pas dans la classe), donc un chemin résiduel = vraie fuite.
_UNIXPATH = re.compile(r"/(?:[\w.\-]+/)+[\w.\-]+")
_WINPATH = re.compile(r"[A-Za-z]:\\[\w.\-\\]+")
# Extension jusqu'à 12 caractères : couvre les extensions de ransomware
# (.lockbit, .encrypted, .cryptolocker), qui portent un signal fort.
_EXT = re.compile(r"(\.[A-Za-z0-9]{1,12})$")
_TOKEN = re.compile(r"<([A-Z]+)_(\d+)>")


def _is_internal(ip: str) -> bool:
    """IP privée / loopback / lien-local / réservée / CGNAT → actif interne."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Anonymizer:
    """Attribue des jetons stables et réversibles.

    Amorcé avec une correspondance existante (jeton→valeur), il réutilise les
    mêmes jetons : un incident re-trié produit exactement les mêmes
    pseudonymes, condition de la comparabilité entre passages.
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
        """IP interne → jeton ; IP publique (IOC attaquant) → clair.

        Une valeur qui n'est PAS une IP est masquée, pas laissée passer :
        `_est_interne` rend False sur une chaîne non parsable, ce qui la faisait
        sortir en clair. Un champ d'IP qui contient autre chose est une donnée
        inattendue — on ne sait pas ce qu'elle porte, donc on la traite comme
        sensible. Fail-closed, comme le reste du module.
        """
        v = str(value)
        try:
            publique = ipaddress.ip_address(v).is_global
        except ValueError:
            return self.token(v, "DIVERS")
        return v if publique else self.token(v, "IP")

    def account(self, value: str) -> str:
        if str(value).strip().lower() in GENERIC_ACCOUNTS:
            return value
        return self.token(value, "COMPTE")

    def object(self, value: str) -> str:
        """Fichier/processus/hash concerné (champ `entity`)."""
        v = str(value)
        if _HASH.match(v):
            return v  # hash malware = IOC externe, gardé en clair
        if "/" in v or "\\" in v:
            return self.path(v)
        return self.token(v, "OBJET")

    def path(self, p: str) -> str:
        """Garde la catégorie (1er segment) et l'extension, tokenise le milieu.

        `/home/jdupont/rapport.xlsx` → `/home/<FICHIER_1>.xlsx`. La catégorie
        (`/home`) et l'extension (`.xlsx`) ne sont pas identifiantes et portent
        du signal ; le milieu (`jdupont/rapport`, qui contient le compte et le
        nom de fichier) est masqué. Le jeton mappe vers ce seul milieu, donc la
        réhydratation reconstruit le chemin exact.
        """
        segs = [s for s in re.split(r"[\\/]", p) if s]
        if not segs:
            return self.token(p, "FICHIER")
        drive = re.match(r"^[A-Za-z]:$", segs[0])
        cat = segs[0]
        remains = "/".join(segs[1:]) if not drive else "\\".join(segs[1:])
        if not remains:  # chemin à un seul segment (p.ex. « procès.exe »)
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
        """Nettoie un champ libre (rule_desc) : remplace les valeurs internes
        déjà connues par leur jeton, puis les e-mails et IP privées résiduels.

        Les CHEMINS sont traités en premier, en entier (via `chemin`) : un
        chemin comme `/home/elie/note.txt` porte un compte et un nom de fichier
        qui, isolés, ne seraient pas dans `interdits`. Les traiter d'abord évite
        de laisser fuiter ces identifiants noyés dans un `rule_desc`.
        """
        out = text
        out = _WINPATH.sub(lambda m: self.path(m.group(0)), out)
        out = _UNIXPATH.sub(lambda m: self.path(m.group(0)), out)
        # Puis les identifiants connus, du plus long au plus court (évite les
        # remplacements partiels). Uniquement des jetons dont la valeur est la
        # chaîne entière (hôte, compte, IP) : jamais les jetons de fichier,
        # dont la valeur est un milieu de chemin — cela casserait la réhydratation.
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
    """Copies pseudonymisées de (incident, alertes) + valeurs interdites.

    Ne touche QUE les champs que render.py consomme. Les originaux (en base)
    ne sont pas modifiés : la pseudonymisation ne vit que sur le chemin
    d'envoi au LLM.
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

        # raw : uniquement les champs d'identifiant lus par _enrichissement.
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
            geo.pop("city_name", None)  # ville : trop fine, droppée
        b["raw"] = raw

        alerts2.append(b)

    # Motifs UEBA : ils portent des VALEURS BRUTES tirées des logs (chemin de
    # binaire, compte, IP), donc de la PII et des actifs client. Sans cette
    # passe, `verifier_fuite` refuserait l'incident — fail-closed — et TOUT ce
    # que le moteur comportemental remonte serait silencieusement écarté du
    # triage. On pseudonymise par TYPE, avec la même méthode que le champ
    # correspondant : un chemin garde sa catégorie et son extension, une IP
    # publique reste en clair (IOC), un compte générique aussi.
    patterns = inc.get("ueba_patterns")
    if isinstance(patterns, list):
        propres = []
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
                    # Tout le reste passe par `objet` — y compris un trait que
                    # ce module ne connaît pas encore. Liste d'EXCLUSION et non
                    # d'inclusion, délibérément : avec une liste d'inclusion,
                    # ajouter un trait dans ueba.py sans y penser ici le laisse
                    # fuiter en clair. Ce n'est pas théorique — le trait
                    # `fichier` a été ajouté après, et `verifier_fuite` a refusé
                    # l'incident (fail-closed), ce qui aurait silencieusement
                    # privé de triage tout ce que le moteur remonte.
                    m["value"] = anon.object(v)
            propres.append(m)
        inc["ueba_patterns"] = propres

    # Passe texte libre sur rule_desc, avec les identifiants collectés.
    forbidden_list = sorted(forbidden)
    # Les notes ("inédit ici, vu sur 2 autres hôtes") sont générées par nous,
    # mais rien n'y interdit un identifiant repris d'un log : on les passe au
    # même filtre que les descriptions de règle.
    for m in (inc.get("ueba_patterns") or []):
        if m.get("note"):
            m["note"] = anon.free_text(str(m["note"]), forbidden_list)
    for b in alerts2:
        if b.get("rule_desc"):
            b["rule_desc"] = anon.free_text(str(b["rule_desc"]),
                                              forbidden_list)

    return inc, alerts2, forbidden_list


def rehydrate(text: str | None, mapping: dict[str, str]) -> str | None:
    """Remplace les jetons par les vraies valeurs (pour l'affichage analyste).

    Du jeton le plus long au plus court : `<FICHIER_11>` avant `<FICHIER_1>`
    (même si le suffixe `>` les rend déjà non préfixes l'un de l'autre).

    Repli sans chevrons : demandé de mettre un jeton en **gras**, le modèle
    écrit parfois `**HOTE_1**` au lieu de `**<HOTE_1>**` — il traite `<...>`
    comme du balisage à nettoyer plutôt qu'un jeton opaque (case #197,
    régression du 2026-08-09 après ajout de la consigne de mise en forme).
    Un remplacement exact du jeton entier laissait alors la forme nue
    intacte, jamais réhydratée. Le nom nu (`HOTE_1`, `IP_3`…) est un jeton
    forgé par ce module (préfixe fixe + compteur) : trop spécifique pour
    matcher un mot du texte par accident, donc sûr en repli.
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
    """Un identifiant interne a survécu à la pseudonymisation."""


def check_leak(text: str, forbidden: list[str]) -> None:
    """Garde-fou fail-closed avant l'envoi cloud.

    Lève si une valeur interne connue, un e-mail ou une IP privée subsiste.
    Les IP publiques sont tolérées (IOC externe gardé en clair, par choix).
    """
    presents = [v for v in forbidden if v and v in text]
    if presents:
        raise LeakError(
            f"identifiant(s) interne(s) non pseudonymisé(s) : {presents}")
    if _EMAIL.search(text):
        raise LeakError("e-mail résiduel dans le texte envoyé au cloud")
    for m in _IPV4.findall(text):
        if _is_internal(m):
            raise LeakError(f"IP privée résiduelle : {m}")
    # Un chemin de fichier résiduel : les jetons `<FICHIER_n>` ne matchent pas
    # (« < » hors classe), donc tout match est un vrai chemin non pseudonymisé.
    for regex in (_UNIXPATH, _WINPATH):
        m = regex.search(text)
        if m:
            raise LeakError(f"chemin résiduel non pseudonymisé : {m.group(0)}")
