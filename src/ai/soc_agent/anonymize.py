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
COMPTES_GENERIQUES = {"root", "administrator", "admin", "system", "guest",
                      "-", "n/a", "none", "localsystem", "networkservice"}

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
_JETON = re.compile(r"<([A-Z]+)_(\d+)>")


def _est_interne(ip: str) -> bool:
    """IP privée / loopback / lien-local / réservée / CGNAT → actif interne."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


class Anonymiseur:
    """Attribue des jetons stables et réversibles.

    Amorcé avec une correspondance existante (jeton→valeur), il réutilise les
    mêmes jetons : un incident re-trié produit exactement les mêmes
    pseudonymes, condition de la comparabilité entre passages.
    """

    def __init__(self, map_existante: dict | None = None):
        self._t2v: dict[str, str] = dict(map_existante or {})
        self._v2t: dict[str, str] = {v: t for t, v in self._t2v.items()}
        self._compteurs: dict[str, int] = {}
        for t in self._t2v:
            m = _JETON.match(t)
            if m:
                p, n = m.group(1), int(m.group(2))
                self._compteurs[p] = max(self._compteurs.get(p, 0), n)

    def jeton(self, valeur: str, prefixe: str) -> str:
        valeur = str(valeur)
        if valeur in self._v2t:
            return self._v2t[valeur]
        n = self._compteurs.get(prefixe, 0) + 1
        self._compteurs[prefixe] = n
        t = f"<{prefixe}_{n}>"
        self._t2v[t] = valeur
        self._v2t[valeur] = t
        return t

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._t2v)

    # --- transformations par type ------------------------------------------

    def ip(self, valeur: str) -> str:
        """IP interne → jeton ; IP publique (IOC attaquant) → clair."""
        return self.jeton(valeur, "IP") if _est_interne(valeur) else valeur

    def compte(self, valeur: str) -> str:
        if str(valeur).strip().lower() in COMPTES_GENERIQUES:
            return valeur
        return self.jeton(valeur, "COMPTE")

    def objet(self, valeur: str) -> str:
        """Fichier/processus/hash concerné (champ `entity`)."""
        v = str(valeur)
        if _HASH.match(v):
            return v  # hash malware = IOC externe, gardé en clair
        if "/" in v or "\\" in v:
            return self.chemin(v)
        return self.jeton(v, "OBJET")

    def chemin(self, p: str) -> str:
        """Garde la catégorie (1er segment) et l'extension, tokenise le milieu.

        `/home/jdupont/rapport.xlsx` → `/home/<FICHIER_1>.xlsx`. La catégorie
        (`/home`) et l'extension (`.xlsx`) ne sont pas identifiantes et portent
        du signal ; le milieu (`jdupont/rapport`, qui contient le compte et le
        nom de fichier) est masqué. Le jeton mappe vers ce seul milieu, donc la
        réhydratation reconstruit le chemin exact.
        """
        segs = [s for s in re.split(r"[\\/]", p) if s]
        if not segs:
            return self.jeton(p, "FICHIER")
        drive = re.match(r"^[A-Za-z]:$", segs[0])
        cat = segs[0]
        reste = "/".join(segs[1:]) if not drive else "\\".join(segs[1:])
        if not reste:  # chemin à un seul segment (p.ex. « procès.exe »)
            m = _EXT.search(cat)
            ext = m.group(1) if m else ""
            milieu = cat[: -len(ext)] if ext else cat
            return f"{self.jeton(milieu, 'FICHIER')}{ext}"
        m = _EXT.search(reste)
        ext = m.group(1) if m else ""
        milieu = reste[: -len(ext)] if ext else reste
        tok = self.jeton(milieu, "FICHIER")
        if drive:
            return f"{cat}\\{tok}{ext}"
        prefixe = "/" if p.startswith("/") else ""
        return f"{prefixe}{cat}/{tok}{ext}"

    def texte_libre(self, texte: str, interdits: list[str]) -> str:
        """Nettoie un champ libre (rule_desc) : remplace les valeurs internes
        déjà connues par leur jeton, puis les e-mails et IP privées résiduels.

        Les CHEMINS sont traités en premier, en entier (via `chemin`) : un
        chemin comme `/home/elie/note.txt` porte un compte et un nom de fichier
        qui, isolés, ne seraient pas dans `interdits`. Les traiter d'abord évite
        de laisser fuiter ces identifiants noyés dans un `rule_desc`.
        """
        out = texte
        out = _WINPATH.sub(lambda m: self.chemin(m.group(0)), out)
        out = _UNIXPATH.sub(lambda m: self.chemin(m.group(0)), out)
        # Puis les identifiants connus, du plus long au plus court (évite les
        # remplacements partiels). Uniquement des jetons dont la valeur est la
        # chaîne entière (hôte, compte, IP) : jamais les jetons de fichier,
        # dont la valeur est un milieu de chemin — cela casserait la réhydratation.
        for v in sorted(interdits, key=len, reverse=True):
            if v and v in out:
                out = out.replace(v, self._v2t.get(v, self.jeton(v, "DIVERS")))
        out = _EMAIL.sub(lambda m: self.jeton(m.group(0), "EMAIL"), out)
        out = _IPV4.sub(
            lambda m: self.jeton(m.group(0), "IP") if _est_interne(m.group(0))
            else m.group(0), out)
        return out


def _raw_dict(raw) -> dict:
    import json
    return raw if isinstance(raw, dict) else json.loads(raw)


def anonymiser(anon: Anonymiseur, incident: dict,
               alertes: list[dict]) -> tuple[dict, list[dict], list[str]]:
    """Copies pseudonymisées de (incident, alertes) + valeurs interdites.

    Ne touche QUE les champs que render.py consomme. Les originaux (en base)
    ne sont pas modifiés : la pseudonymisation ne vit que sur le chemin
    d'envoi au LLM.
    """
    inc = copy.deepcopy(incident)
    interdits: set[str] = set()

    if inc.get("agent_name"):
        interdits.add(str(inc["agent_name"]))
        inc["agent_name"] = anon.jeton(inc["agent_name"], "HOTE")

    alertes2 = []
    for a in alertes:
        b = copy.deepcopy(a)

        if b.get("srcip"):
            if _est_interne(str(b["srcip"])):
                interdits.add(str(b["srcip"]))
            b["srcip"] = anon.ip(str(b["srcip"]))

        if b.get("srcuser") and str(b["srcuser"]).strip().lower() \
                not in COMPTES_GENERIQUES:
            interdits.add(str(b["srcuser"]))
            b["srcuser"] = anon.compte(str(b["srcuser"]))

        if b.get("entity"):
            b["entity"] = anon.objet(str(b["entity"]))

        # raw : uniquement les champs d'identifiant lus par _enrichissement.
        raw = _raw_dict(b.get("raw") or {})
        data = raw.get("data", {})
        abuse = data.get("abuseipdb")
        if isinstance(abuse, dict) and abuse.get("srcip"):
            if _est_interne(str(abuse["srcip"])):
                interdits.add(str(abuse["srcip"]))
            abuse["srcip"] = anon.ip(str(abuse["srcip"]))
        vt = data.get("virustotal")
        if isinstance(vt, dict) and isinstance(vt.get("source"), dict):
            f = vt["source"].get("file")
            if f:
                interdits.add(str(f))
                vt["source"]["file"] = anon.objet(str(f))
        geo = raw.get("GeoLocation")
        if isinstance(geo, dict):
            geo.pop("city_name", None)  # ville : trop fine, droppée
        b["raw"] = raw

        alertes2.append(b)

    # Motifs UEBA : ils portent des VALEURS BRUTES tirées des logs (chemin de
    # binaire, compte, IP), donc de la PII et des actifs client. Sans cette
    # passe, `verifier_fuite` refuserait l'incident — fail-closed — et TOUT ce
    # que le moteur comportemental remonte serait silencieusement écarté du
    # triage. On pseudonymise par TYPE, avec la même méthode que le champ
    # correspondant : un chemin garde sa catégorie et son extension, une IP
    # publique reste en clair (IOC), un compte générique aussi.
    motifs = inc.get("ueba_motifs")
    if isinstance(motifs, list):
        propres = []
        for m in motifs:
            m = dict(m)
            v = m.get("valeur")
            if v:
                v = str(v)
                trait = m.get("trait")
                if trait in ("exe", "parent_child"):
                    m["valeur"] = anon.objet(v)
                elif trait == "compte":
                    if v.strip().lower() not in COMPTES_GENERIQUES:
                        interdits.add(v)
                    m["valeur"] = anon.compte(v)
                elif trait == "srcip":
                    if _est_interne(v):
                        interdits.add(v)
                    m["valeur"] = anon.ip(v)
                # pays / heure / dst_port / rule_id : des ATTRIBUTS, pas des
                # identifiants. Ils portent le signal et sortent verbatim.
            propres.append(m)
        inc["ueba_motifs"] = propres

    # Passe texte libre sur rule_desc, avec les identifiants collectés.
    liste_interdits = sorted(interdits)
    # Les notes ("inédit ici, vu sur 2 autres hôtes") sont générées par nous,
    # mais rien n'y interdit un identifiant repris d'un log : on les passe au
    # même filtre que les descriptions de règle.
    for m in (inc.get("ueba_motifs") or []):
        if m.get("note"):
            m["note"] = anon.texte_libre(str(m["note"]), liste_interdits)
    for b in alertes2:
        if b.get("rule_desc"):
            b["rule_desc"] = anon.texte_libre(str(b["rule_desc"]),
                                              liste_interdits)

    return inc, alertes2, liste_interdits


def rehydrater(texte: str | None, mapping: dict[str, str]) -> str | None:
    """Remplace les jetons par les vraies valeurs (pour l'affichage analyste).

    Du jeton le plus long au plus court : `<FICHIER_11>` avant `<FICHIER_1>`
    (même si le suffixe `>` les rend déjà non préfixes l'un de l'autre).
    """
    if not texte:
        return texte
    for token in sorted(mapping, key=len, reverse=True):
        texte = texte.replace(token, mapping[token])
    return texte


class FuiteError(RuntimeError):
    """Un identifiant interne a survécu à la pseudonymisation."""


def verifier_fuite(texte: str, interdits: list[str]) -> None:
    """Garde-fou fail-closed avant l'envoi cloud.

    Lève si une valeur interne connue, un e-mail ou une IP privée subsiste.
    Les IP publiques sont tolérées (IOC externe gardé en clair, par choix).
    """
    presents = [v for v in interdits if v and v in texte]
    if presents:
        raise FuiteError(
            f"identifiant(s) interne(s) non pseudonymisé(s) : {presents}")
    if _EMAIL.search(texte):
        raise FuiteError("e-mail résiduel dans le texte envoyé au cloud")
    for m in _IPV4.findall(texte):
        if _est_interne(m):
            raise FuiteError(f"IP privée résiduelle : {m}")
    # Un chemin de fichier résiduel : les jetons `<FICHIER_n>` ne matchent pas
    # (« < » hors classe), donc tout match est un vrai chemin non pseudonymisé.
    for regex in (_UNIXPATH, _WINPATH):
        m = regex.search(texte)
        if m:
            raise FuiteError(f"chemin résiduel non pseudonymisé : {m.group(0)}")
