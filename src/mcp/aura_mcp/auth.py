"""Authentification et autorisation du serveur MCP AURA.

Deux étages, volontairement séparés :

- **Middleware ASGI** : valide le jeton une fois par requête HTTP et dépose
  les scopes dans un contextvar. C'est le seul endroit qui voit le JWT.
- **Décorateur `exige`** : vérifie le scope de l'outil appelé. Le middleware
  ne peut pas le faire — au moment de la requête HTTP, on ne sait pas encore
  quel outil le corps JSON-RPC va invoquer.

Sans le décorateur, un jeton `aura:read` pourrait appeler `aura_isolate`.
Tout outil non décoré est donc un trou : `serveur.py` refuse d'en enregistrer.
"""

import time
from collections import defaultdict, deque
from contextvars import ContextVar
from functools import wraps

import jwt
from starlette.responses import JSONResponse

from . import config

# Scopes du jeton porté par la requête en cours. Vide = non authentifié : le
# défaut est le refus, pas la lecture.
SCOPES: ContextVar[frozenset[str]] = ContextVar("scopes", default=frozenset())
SUJET: ContextVar[str] = ContextVar("sujet", default="anonyme")


class Refus(Exception):
    """Scope insuffisant. Remonte au client comme une erreur d'outil.

    Message volontairement explicite (« il faut aura:admin ») : le client est
    un agent IA, pas un attaquant anonyme — il doit pouvoir dire à son
    utilisateur quel jeton demander plutôt que boucler sur un échec opaque.
    """


def scopes_du_jeton(token: str) -> tuple[str, frozenset[str]]:
    """(sujet, scopes effectifs). Lève `jwt.PyJWTError` si le jeton est mauvais.

    Les scopes sont *développés* par implication : `aura:admin` donne aussi
    write et read, sinon chaque jeton devrait lister les trois et un oubli
    passerait pour un refus incompréhensible.
    """
    charge = jwt.decode(token, config.SECRET, algorithms=["HS256"],
                        audience=config.AUDIENCE, issuer=config.ISSUER,
                        options={"require": ["exp", "sub"]})
    brut = charge.get("scope", "")
    demandes = set(brut.split()) if isinstance(brut, str) else set(brut)
    effectifs: set[str] = set()
    for s in demandes:
        effectifs |= config.IMPLIQUE.get(s, set())
    return charge["sub"], frozenset(effectifs)


def exige(scope: str):
    """Décorateur d'outil : impose un scope minimal.

    S'applique à des fonctions synchrones comme asynchrones — les outils de
    lecture appellent psycopg en bloquant, ceux du gateway sont async.
    """
    def decorateur(fn):
        @wraps(fn)
        def sync(*a, **kw):
            _verifier(scope, fn.__name__)
            return fn(*a, **kw)

        @wraps(fn)
        async def asynchrone(*a, **kw):
            _verifier(scope, fn.__name__)
            return await fn(*a, **kw)

        enveloppe = asynchrone if _est_async(fn) else sync
        enveloppe.scope_requis = scope  # lu par serveur.py pour l'inventaire
        return enveloppe
    return decorateur


def _est_async(fn) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


def _verifier(scope: str, nom: str) -> None:
    if scope not in SCOPES.get():
        raise Refus(
            f"L'outil {nom} demande le scope {scope}. Le jeton présenté porte "
            f"{' '.join(sorted(SCOPES.get())) or 'aucun scope'}.")


class Authentification:
    """Middleware ASGI : Bearer JWT obligatoire sur le chemin MCP.

    `/health` reste ouvert — c'est le healthcheck du conteneur, il ne révèle
    que l'état vivant/mort.
    """

    def __init__(self, app):
        self.app = app
        self._appels: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        entetes = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        pair = entetes.get("authorization", "").split(" ", 1)
        if len(pair) != 2 or pair[0].lower() != "bearer":
            await _erreur(send, 401, "Jeton Bearer requis.")
            return

        try:
            sujet, scopes = scopes_du_jeton(pair[1])
        except jwt.PyJWTError as e:
            await _erreur(send, 401, f"Jeton refusé : {e}")
            return
        if not scopes:
            await _erreur(send, 403,
                          "Jeton sans scope AURA reconnu (aura:read / "
                          "aura:write / aura:admin).")
            return

        if not self._sous_le_debit(sujet):
            await _erreur(send, 429,
                          f"Plus de {config.DEBIT_MAX} appels par minute.")
            return

        jeton_scopes = SCOPES.set(scopes)
        jeton_sujet = SUJET.set(sujet)
        try:
            await self.app(scope, receive, send)
        finally:
            SCOPES.reset(jeton_scopes)
            SUJET.reset(jeton_sujet)

    def _sous_le_debit(self, sujet: str) -> bool:
        """Fenêtre glissante d'une minute, comptée par sujet du jeton.

        Par sujet et non par IP : tous les clients arrivent de la loopback,
        l'IP ne distingue rien.
        """
        maintenant = time.monotonic()
        recents = self._appels[sujet]
        while recents and maintenant - recents[0] > 60:
            recents.popleft()
        if len(recents) >= config.DEBIT_MAX:
            return False
        recents.append(maintenant)
        return True


async def _vide():
    """`receive` factice : une réponse d'erreur ne lit jamais le corps."""
    return {"type": "http.disconnect"}


async def _erreur(send, code: int, message: str) -> None:
    reponse = JSONResponse({"error": message}, status_code=code)
    await reponse({"type": "http"}, _vide, send)
