"""Authentication and authorization for the AURA MCP server.

Two stages, deliberately separated:

- **ASGI middleware**: validates the token once per HTTP request and deposits
  the scopes in a contextvar. It is the only place that sees the JWT.
- **`require` decorator**: checks the scope of the called tool. The
  middleware can't do it — at HTTP request time we don't yet know which tool
  the JSON-RPC body will invoke.

Without the decorator, an `aura:read` token could call `aura_isolate`.
Any undecorated tool is therefore a hole: `server.py` refuses to register it.
"""

import time
from collections import defaultdict, deque
from contextvars import ContextVar
from functools import wraps

import jwt
from starlette.responses import JSONResponse

from . import config

# Scopes carried by the request currently in flight. Empty = unauthenticated:
# the default is refusal, not read access.
SCOPES: ContextVar[frozenset[str]] = ContextVar("scopes", default=frozenset())
SUBJECT: ContextVar[str] = ContextVar("subject", default="anonymous")


class Denied(Exception):
    """Insufficient scope. Surfaces to the client as a tool error.

    Deliberately explicit message ("aura:admin is required"): the client is
    an AI agent, not an anonymous attacker — it must be able to tell its
    user which token to request instead of looping on an opaque failure.
    """


def scopes_of_token(token: str) -> tuple[str, frozenset[str]]:
    """(subject, effective scopes). Raises `jwt.PyJWTError` if the token is bad.

    Scopes are *expanded* by implication: `aura:admin` also grants write and
    read, otherwise every token would need to list all three and an omission
    would look like an incomprehensible refusal.
    """
    payload = jwt.decode(token, config.SECRET, algorithms=["HS256"],
                        audience=config.AUDIENCE, issuer=config.ISSUER,
                        options={"require": ["exp", "sub"]})
    raw = payload.get("scope", "")
    requested = set(raw.split()) if isinstance(raw, str) else set(raw)
    effective: set[str] = set()
    for s in requested:
        effective |= config.IMPLIES.get(s, set())
    return payload["sub"], frozenset(effective)


def require(scope: str):
    """Tool decorator: enforces a minimum scope.

    Applies to both sync and async functions — read tools call psycopg in a
    blocking way, gateway tools are async.
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
        envelope.required_scope = scope  # read by server.py for the inventory
        return envelope
    return decorator


def _is_async(fn) -> bool:
    import inspect
    return inspect.iscoroutinefunction(fn)


def _verify(scope: str, name: str) -> None:
    if scope not in SCOPES.get():
        raise Denied(
            f"Tool {name} requires scope {scope}. The presented token "
            f"carries {' '.join(sorted(SCOPES.get())) or 'no scope'}.")


class Authentication:
    """ASGI middleware: Bearer JWT required on the MCP path.

    `/health` stays open — it's the container's healthcheck, it reveals
    nothing but the alive/dead state.
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
            await _error(send, 401, "Bearer token required.")
            return

        try:
            subject, scopes = scopes_of_token(pair[1])
        except jwt.PyJWTError as e:
            await _error(send, 401, f"Token rejected: {e}")
            return
        if not scopes:
            await _error(send, 403,
                          "Token without a recognized AURA scope (aura:read / "
                          "aura:write / aura:admin).")
            return

        if not self._under_rate_limit(subject):
            await _error(send, 429,
                          f"More than {config.MAX_RATE} calls per minute.")
            return

        token_scopes = SCOPES.set(scopes)
        token_subject = SUBJECT.set(subject)
        try:
            await self.app(scope, receive, send)
        finally:
            SCOPES.reset(token_scopes)
            SUBJECT.reset(token_subject)

    def _under_rate_limit(self, subject: str) -> bool:
        """One-minute sliding window, counted per token subject.

        Per subject and not per IP: every client arrives from loopback, the
        IP doesn't distinguish anything.
        """
        now = time.monotonic()
        recent = self._calls[subject]
        while recent and now - recent[0] > 60:
            recent.popleft()
        if len(recent) >= config.MAX_RATE:
            return False
        recent.append(now)
        return True


async def _empty():
    """Dummy `receive`: an error response never reads the body."""
    return {"type": "http.disconnect"}


async def _error(send, code: int, message: str) -> None:
    response = JSONResponse({"error": message}, status_code=code)
    await response({"type": "http"}, _empty, send)
