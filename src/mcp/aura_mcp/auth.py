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
SUBJECT: ContextVar[str] = ContextVar("sujet", default="anonyme")


class Denied(Exception):
    """Scope insuffisant. Remonte au client comme une erreur d'outil.

    Message volontairement explicite (« il faut aura:admin ») : le client est
    un agent IA, pas un attaquant anonyme — il doit pouvoir dire à son
    utilisateur quel jeton demander plutôt que boucler sur un échec opaque.
    """


def scopes_of_token(token: str) -> tuple[str, frozenset[str]]:
    """(sujet, scopes effectifs). Lève `jwt.PyJWTError` si le jeton est mauvais.

    Les scopes sont *développés* par implication : `aura:admin` donne aussi
    write et read, sinon chaque jeton devrait lister les trois et un oubli
    passerait pour un refus incompréhensible.
    """
    charge = jwt.decode(token, config.SECRET, algorithms=["HS256"],
                        audience=config.AUDIENCE, issuer=config.ISSUER,
                        options={"require": ["exp", "sub"]})
    raw = charge.get("scope", "")
    requests = set(raw.split()) if isinstance(raw, str) else set(raw)
    effective: set[str] = set()
    for s in requests:
        effective |= config.IMPLIES.get(s, set())
    return charge["sub"], frozenset(effective)


def require(scope: str):
    """Décorateur d'outil : impose un scope minimal.

    S'applique à des fonctions synchrones comme asynchrones — les outils de
    lecture appellent psycopg en bloquant, ceux du gateway sont async.
    """
    def decorator(fn):
        @wraps(fn)
        def sync(*a, **kw):
            _verify(scope, fn.__name__)
            return fn(*a, **kw)

        @wraps(fn)
        async def asynchronous(*a, **kw):
            _verify(scope, fn.__name__)
            return await fn(*a, **kw)

        envelope = asynchronous if _is_async(fn) else sync
        envelope.required_scope = scope  # lu par serveur.py pour l'inventaire
        return envelope
    return decorator


def _is_async(fn) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


def _verify(scope: str, name: str) -> None:
    if scope not in SCOPES.get():
        raise Denied(
            f"L'outil {name} demande le scope {scope}. Le jeton présenté porte "
            f"{' '.join(sorted(SCOPES.get())) or 'aucun scope'}.")


class Authentication:
    """Middleware ASGI : Bearer JWT obligatoire sur le chemin MCP.

    `/health` reste ouvert — c'est le healthcheck du conteneur, il ne révèle
    que l'état vivant/mort.
    """

    def __init__(self, app):
        self.app = app
        self._calls: dict[str, deque[float]] = defaultdict(deque)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
        pair = headers.get("authorization", "").split(" ", 1)
        if len(pair) != 2 or pair[0].lower() != "bearer":
            await _error(send, 401, "Jeton Bearer requis.")
            return

        try:
            subject, scopes = scopes_of_token(pair[1])
        except jwt.PyJWTError as e:
            await _error(send, 401, f"Jeton refusé : {e}")
            return
        if not scopes:
            await _error(send, 403,
                          "Jeton sans scope AURA reconnu (aura:read / "
                          "aura:write / aura:admin).")
            return

        if not self._under_rate_limit(subject):
            await _error(send, 429,
                          f"Plus de {config.MAX_RATE} appels par minute.")
            return

        token_scopes = SCOPES.set(scopes)
        token_subject = SUBJECT.set(subject)
        try:
            await self.app(scope, receive, send)
        finally:
            SCOPES.reset(token_scopes)
            SUBJECT.reset(token_subject)

    def _under_rate_limit(self, subject: str) -> bool:
        """Fenêtre glissante d'une minute, comptée par sujet du jeton.

        Par sujet et non par IP : tous les clients arrivent de la loopback,
        l'IP ne distingue rien.
        """
        maintenant = time.monotonic()
        recent = self._calls[subject]
        while recent and maintenant - recent[0] > 60:
            recent.popleft()
        if len(recent) >= config.MAX_RATE:
            return False
        recent.append(maintenant)
        return True


async def _empty():
    """`receive` factice : une réponse d'erreur ne lit jamais le corps."""
    return {"type": "http.disconnect"}


async def _error(send, code: int, message: str) -> None:
    response = JSONResponse({"error": message}, status_code=code)
    await response({"type": "http"}, _empty, send)
