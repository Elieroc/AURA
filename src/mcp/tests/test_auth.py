"""What the MCP server must never let through.

These tests cover the authorization invariants, not the tools' behaviour: a
tool that returns bad data is a bug, a tool reachable by the wrong token is an
open door into production.
"""

import pytest

from aura_mcp import auth, gateway


def _scopes(*values):
    """Installs scopes for the duration of a test."""
    return auth.SCOPES.set(frozenset(values))


def test_default_is_deny():
    """A call with no token has no right at all — not even read.

    The upstream Wazuh MCP server grants read by default. Here even read
    exposes incident logs: nothing is implicit.
    """
    assert auth.SCOPES.get() == frozenset()

    @auth.require("aura:read")
    def tool():
        return "reached"

    with pytest.raises(auth.Denied):
        tool()


def test_admin_implies_write_and_read():
    """An admin token does not have to list all three scopes."""
    token = _scopes(*auth.config.IMPLIES["aura:admin"])
    try:
        @auth.require("aura:read")
        def read():
            return "ok"

        @auth.require("aura:admin")
        def act():
            return "ok"

        assert read() == "ok"
        assert act() == "ok"
    finally:
        auth.SCOPES.reset(token)


def test_read_does_not_grant_action():
    """The case that matters: a read token must not be able to isolate."""
    token = _scopes("aura:read")
    try:
        @auth.require("aura:admin")
        def isolate():
            return "isolated"

        with pytest.raises(auth.Denied) as e:
            isolate()
        # The message must name the missing scope: the client is an AI agent
        # that must be able to tell its user which token to request.
        assert "aura:admin" in str(e.value)
    finally:
        auth.SCOPES.reset(token)


def test_scopeless_tool_refused_at_registration():
    """A tool that forgets @auth.require must not be servable."""
    from aura_mcp import server

    def negligent_tool():
        return "accessible to any valid token"

    with pytest.raises(RuntimeError, match="auth.require"):
        server.register(negligent_tool)


def test_token_scopes_expand_the_implications():
    import datetime as dt

    import jwt

    now = dt.datetime.now(dt.timezone.utc)
    raw = jwt.encode(
        {"sub": "test", "scope": "aura:admin", "iss": auth.config.ISSUER,
         "aud": auth.config.AUDIENCE, "iat": now,
         "exp": now + dt.timedelta(minutes=5)},
        auth.config.SECRET, algorithm="HS256")

    subject, scopes = auth.scopes_of_token(raw)
    assert subject == "test"
    assert scopes == frozenset({"aura:admin", "aura:write", "aura:read"})


def test_expired_token_refused():
    import datetime as dt

    import jwt

    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=2)
    raw = jwt.encode(
        {"sub": "test", "scope": "aura:read", "iss": auth.config.ISSUER,
         "aud": auth.config.AUDIENCE, "iat": past,
         "exp": past + dt.timedelta(minutes=5)},
        auth.config.SECRET, algorithm="HS256")

    with pytest.raises(jwt.PyJWTError):
        auth.scopes_of_token(raw)


# --- Relay ------------------------------------------------------------------

def test_wazuh_active_response_always_masked():
    """The non-negotiable point of the relay.

    These tools talk to the manager's API with no knowledge at all of the
    protected agents or the infrastructure groups. A client that sees them can
    isolate the firewall — and cut off the SOC with it.
    """
    upstream = gateway.Upstream("wazuh", "http://x/mcp", "", "wazuh_")
    for tool in gateway.WAZUH_MASKED:
        assert not gateway.allowed(upstream, tool), tool


def test_allowlist_not_denylist():
    """An unknown tool is not relayed.

    This is what keeps an upstream version bump from exposing a new action
    tool on its own.
    """
    upstream = gateway.Upstream("wazuh", "http://x/mcp", "", "wazuh_")
    assert not gateway.allowed(upstream, "tool_added_by_an_update")
    assert gateway.allowed(upstream, "get_wazuh_agents")


def test_no_masked_tool_in_the_allowlist():
    """Guardrail against a contradiction introduced by carelessness."""
    assert not (gateway.WAZUH_ALLOWED & gateway.WAZUH_MASKED)
