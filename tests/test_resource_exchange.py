"""Tests for identity.resource_exchange — ID-JAG → access token exchange."""
from __future__ import annotations

import time

import httpx
import jwt
import pytest
import respx

from identity.resource_exchange import (
    DEFAULT_RESOURCE_AUTH_CLIENT_ID,
    DEFAULT_RESOURCE_AUTH_SERVER_URL,
    JWT_BEARER_GRANT,
    CachedTokenStore,
    ResourceAccessToken,
    ResourceExchangeError,
    TokenExpiredError,
    exchange_id_jag_for_access_token,
    validate_access_token,
)


TOKEN_URL = f"{DEFAULT_RESOURCE_AUTH_SERVER_URL}/oauth2/token"
HS256_SECRET = "test-secret"  # matches LOCAL_SIGNING_KEY convention in the POC


def _hs256(payload: dict) -> str:
    return jwt.encode(payload, HS256_SECRET, algorithm="HS256")


@respx.mock
def test_exchange_success_returns_populated_token():
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "minted.access.token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read write",
            },
        )
    )

    before = int(time.time())
    result = exchange_id_jag_for_access_token(id_jag="id-jag-assertion")
    after = int(time.time())

    assert result.access_token == "minted.access.token"
    assert result.token_type == "Bearer"
    assert result.expires_in == 3600
    assert result.scope == "read write"
    assert before + 3600 <= result.expires_at <= after + 3600

    assert route.called
    sent = route.calls.last.request
    assert sent.headers["content-type"] == "application/x-www-form-urlencoded"
    body = dict(httpx.QueryParams(sent.content.decode()))
    assert body == {
        "grant_type": JWT_BEARER_GRANT,
        "assertion": "id-jag-assertion",
        "client_id": DEFAULT_RESOURCE_AUTH_CLIENT_ID,
        "scope": "read write",
    }


@respx.mock
def test_exchange_honors_client_id_and_scope_overrides():
    route = respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "t",
                "token_type": "Bearer",
                "expires_in": 60,
                "scope": "read",
            },
        )
    )

    exchange_id_jag_for_access_token(
        id_jag="a", client_id="custom-client", scope="read"
    )

    body = dict(httpx.QueryParams(route.calls.last.request.content.decode()))
    assert body["client_id"] == "custom-client"
    assert body["scope"] == "read"


@respx.mock
def test_exchange_raises_on_invalid_grant():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "invalid_grant",
                "error_description": "assertion signature/claims invalid",
            },
        )
    )

    with pytest.raises(ResourceExchangeError) as excinfo:
        exchange_id_jag_for_access_token(id_jag="bad")

    err = excinfo.value
    assert err.error == "invalid_grant"
    assert "signature" in err.description
    assert err.status_code == 400


@respx.mock
def test_exchange_raises_on_unsupported_grant_type():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            400,
            json={
                "error": "unsupported_grant_type",
                "error_description": "grant_type must be jwt-bearer",
            },
        )
    )

    with pytest.raises(ResourceExchangeError) as excinfo:
        exchange_id_jag_for_access_token(id_jag="x")
    assert excinfo.value.error == "unsupported_grant_type"


@respx.mock
def test_exchange_raises_on_non_json_error_body():
    respx.post(TOKEN_URL).mock(
        return_value=httpx.Response(500, text="gateway fell over")
    )

    with pytest.raises(ResourceExchangeError) as excinfo:
        exchange_id_jag_for_access_token(id_jag="x")

    assert excinfo.value.status_code == 500
    assert excinfo.value.error == "server_error"
    assert "gateway" in excinfo.value.description


@respx.mock
def test_exchange_propagates_network_error():
    respx.post(TOKEN_URL).mock(side_effect=httpx.ConnectError("refused"))

    with pytest.raises(httpx.ConnectError):
        exchange_id_jag_for_access_token(id_jag="x")


@respx.mock
def test_exchange_respects_env_override(monkeypatch):
    monkeypatch.setenv("RESOURCE_AUTH_SERVER_URL", "https://alt.example.com")
    monkeypatch.setenv("RESOURCE_AUTH_CLIENT_ID", "env-client")
    route = respx.post("https://alt.example.com/oauth2/token").mock(
        return_value=httpx.Response(
            200,
            json={"access_token": "t", "token_type": "Bearer", "expires_in": 1, "scope": ""},
        )
    )

    exchange_id_jag_for_access_token(id_jag="x")

    assert route.called
    body = dict(httpx.QueryParams(route.calls.last.request.content.decode()))
    assert body["client_id"] == "env-client"


def test_validate_access_token_returns_claims_for_valid_token():
    now = int(time.time())
    token = _hs256(
        {"sub": "sarah@example.com", "exp": now + 600, "scope": "read"}
    )

    claims = validate_access_token(token)

    assert claims["sub"] == "sarah@example.com"
    assert claims["scope"] == "read"


def test_validate_access_token_raises_on_expired_token():
    now = int(time.time())
    token = _hs256({"sub": "sarah@example.com", "exp": now - 1})

    with pytest.raises(TokenExpiredError) as excinfo:
        validate_access_token(token)
    assert excinfo.value.exp == now - 1


def test_validate_access_token_without_exp_is_accepted():
    """Token with no exp claim: no expiry to check, just return claims."""
    token = _hs256({"sub": "sarah@example.com"})
    claims = validate_access_token(token)
    assert claims["sub"] == "sarah@example.com"


def test_validate_access_token_rejects_garbage():
    with pytest.raises(jwt.DecodeError):
        validate_access_token("not-a-jwt")


def test_cache_miss_returns_none():
    store = CachedTokenStore()
    assert store.get("c", "read", "sub") is None


def test_cache_hit_returns_stored_token():
    store = CachedTokenStore()
    token = ResourceAccessToken(
        access_token="t",
        token_type="Bearer",
        expires_in=3600,
        scope="read",
        expires_at=int(time.time()) + 3600,
    )
    store.set("c", "read", "sub", token)
    assert store.get("c", "read", "sub") is token


def test_cache_miss_on_expired_entry_and_auto_invalidates():
    store = CachedTokenStore(expiry_skew_seconds=0)
    expired = ResourceAccessToken(
        access_token="old",
        token_type="Bearer",
        expires_in=60,
        scope="read",
        expires_at=int(time.time()) - 1,
    )
    store.set("c", "read", "sub", expired)

    assert store.get("c", "read", "sub") is None
    # second lookup also miss — entry was invalidated, not just filtered
    assert store._entries == {}  # type: ignore[attr-defined]


def test_cache_miss_within_skew_window():
    """A token 10s from expiry misses when skew=30s (treated as expired)."""
    store = CachedTokenStore(expiry_skew_seconds=30)
    near_expiry = ResourceAccessToken(
        access_token="t",
        token_type="Bearer",
        expires_in=10,
        scope="read",
        expires_at=int(time.time()) + 10,
    )
    store.set("c", "read", "sub", near_expiry)
    assert store.get("c", "read", "sub") is None


def test_cache_keys_are_distinct_per_tuple_component():
    store = CachedTokenStore()
    exp = int(time.time()) + 3600

    def mk(tag: str) -> ResourceAccessToken:
        return ResourceAccessToken(
            access_token=tag,
            token_type="Bearer",
            expires_in=3600,
            scope="read",
            expires_at=exp,
        )

    store.set("c1", "read", "sub1", mk("a"))
    store.set("c2", "read", "sub1", mk("b"))
    store.set("c1", "read write", "sub1", mk("c"))
    store.set("c1", "read", "sub2", mk("d"))

    assert store.get("c1", "read", "sub1").access_token == "a"
    assert store.get("c2", "read", "sub1").access_token == "b"
    assert store.get("c1", "read write", "sub1").access_token == "c"
    assert store.get("c1", "read", "sub2").access_token == "d"
