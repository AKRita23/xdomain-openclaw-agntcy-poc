"""Tests for :mod:`identity.xaa_dev_client`.

Covers PKCE pair shape, the three POST endpoints (authorization_code,
token-exchange, jwt-bearer) with success and error bodies, and that
every call uses ``client_secret_post`` (credentials in the form body,
never in an ``Authorization: Basic`` header).
"""
from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from identity.xaa_dev_client import (
    ID_JAG_TOKEN_TYPE,
    ID_TOKEN_TYPE,
    JWT_BEARER_GRANT,
    TOKEN_EXCHANGE_GRANT,
    XAADevClient,
    XAADevConfig,
    XAADevError,
    generate_pkce_pair,
)


IDP = "https://idp.xaa.dev"
AUTH = "https://auth.resource.xaa.dev"
RESOURCE_AUD = "http://weather-slack-resources.com"


@pytest.fixture
def config() -> XAADevConfig:
    return XAADevConfig(
        idp_url=IDP,
        auth_server_url=AUTH,
        client_id="xaa-client-main",
        client_secret="xaa-secret-main",
        resource_client_id="xaa-client-main-at-res_abc",
        resource_client_secret="xaa-secret-res",
        redirect_uri="http://localhost:8000/callback",
        resource_audience=RESOURCE_AUD,
        scope="openid email",
    )


@pytest.fixture
def client(config) -> XAADevClient:
    return XAADevClient(config)


# --------------------------------------------------------------------------- PKCE


def test_generate_pkce_pair_produces_valid_s256_challenge():
    verifier, challenge = generate_pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert "=" not in challenge  # S256 strips padding
    assert "/" not in challenge and "+" not in challenge  # urlsafe alphabet

    # Recompute and compare
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    assert challenge == expected


def test_generate_pkce_pair_returns_unique_pairs():
    v1, c1 = generate_pkce_pair()
    v2, c2 = generate_pkce_pair()
    assert v1 != v2 and c1 != c2


# --------------------------------------------------------------------------- Step 1A


@pytest.mark.asyncio
async def test_build_authorize_url_includes_pkce_and_state(client):
    url = await client.build_authorize_url(
        state="abc-state", code_challenge="chal-xyz",
    )
    assert url.startswith(f"{IDP}/authorize?")
    parsed = urlparse(url)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    assert params == {
        "response_type": "code",
        "scope": "openid email",
        "redirect_uri": "http://localhost:8000/callback",
        "client_id": "xaa-client-main",
        "code_challenge_method": "S256",
        "code_challenge": "chal-xyz",
        "state": "abc-state",
    }


# --------------------------------------------------------------------------- Step 1B


@pytest.mark.asyncio
async def test_exchange_code_for_id_token_sends_client_secret_post(client):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{IDP}/token").mock(
            return_value=httpx.Response(200, json={
                "id_token": "id-token-value",
                "access_token": "user-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
            })
        )
        result = await client.exchange_code_for_id_token(
            code="auth-code-xyz", code_verifier="verifier-xyz",
        )

    assert result["id_token"] == "id-token-value"

    request = route.calls[0].request
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    # Critical: credentials in body, no Basic auth
    assert "authorization" not in {k.lower() for k in request.headers.keys()}
    body = parse_qs(request.content.decode())
    assert body["grant_type"] == ["authorization_code"]
    assert body["code"] == ["auth-code-xyz"]
    assert body["code_verifier"] == ["verifier-xyz"]
    assert body["client_id"] == ["xaa-client-main"]
    assert body["client_secret"] == ["xaa-secret-main"]
    assert body["redirect_uri"] == ["http://localhost:8000/callback"]


@pytest.mark.asyncio
async def test_exchange_code_for_id_token_raises_xaadev_error_with_oauth_code(
    client,
):
    with respx.mock:
        respx.post(f"{IDP}/token").mock(
            return_value=httpx.Response(400, json={
                "error": "invalid_grant",
                "error_description": "code expired",
            })
        )
        with pytest.raises(XAADevError) as excinfo:
            await client.exchange_code_for_id_token(
                code="stale", code_verifier="v",
            )

    err = excinfo.value
    assert err.status_code == 400
    assert err.error_code == "invalid_grant"
    assert err.request_url == f"{IDP}/token"
    assert "invalid_grant" in str(err)


# --------------------------------------------------------------------------- Step 2


@pytest.mark.asyncio
async def test_exchange_id_token_for_id_jag_sends_token_exchange_params(client):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{IDP}/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "id-jag-assertion",
                "issued_token_type": ID_JAG_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": 300,
            })
        )
        result = await client.exchange_id_token_for_id_jag(
            id_token="sarah-id-token",
        )

    assert result["access_token"] == "id-jag-assertion"
    assert result["issued_token_type"] == ID_JAG_TOKEN_TYPE

    body = parse_qs(route.calls[0].request.content.decode())
    assert body["grant_type"] == [TOKEN_EXCHANGE_GRANT]
    assert body["requested_token_type"] == [ID_JAG_TOKEN_TYPE]
    assert body["subject_token_type"] == [ID_TOKEN_TYPE]
    assert body["subject_token"] == ["sarah-id-token"]
    assert body["audience"] == [AUTH]
    assert body["resource"] == [RESOURCE_AUD]
    assert body["client_id"] == ["xaa-client-main"]
    assert body["client_secret"] == ["xaa-secret-main"]
    # Credentials never in Basic auth
    auth_hdr = route.calls[0].request.headers.get("authorization")
    assert auth_hdr is None or not auth_hdr.lower().startswith("basic ")


@pytest.mark.asyncio
async def test_exchange_id_token_for_id_jag_401_maps_to_xaadev_error(client):
    with respx.mock:
        respx.post(f"{IDP}/token").mock(
            return_value=httpx.Response(401, json={
                "error": "invalid_client",
                "error_description": "bad client secret",
            })
        )
        with pytest.raises(XAADevError) as excinfo:
            await client.exchange_id_token_for_id_jag(id_token="x")

    assert excinfo.value.status_code == 401
    assert excinfo.value.error_code == "invalid_client"


# --------------------------------------------------------------------------- Step 3


@pytest.mark.asyncio
async def test_exchange_id_jag_for_access_token_hits_auth_server_host(client):
    """Step 3 must hit the auth-server host, not the IdP host."""
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(f"{AUTH}/token").mock(
            return_value=httpx.Response(200, json={
                "access_token": "scoped-at",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "openid email",
            })
        )
        result = await client.exchange_id_jag_for_access_token(
            id_jag="the-id-jag",
        )

    assert result["access_token"] == "scoped-at"
    assert route.calls[0].request.url.host == "auth.resource.xaa.dev"

    body = parse_qs(route.calls[0].request.content.decode())
    assert body["grant_type"] == [JWT_BEARER_GRANT]
    assert body["assertion"] == ["the-id-jag"]
    # Resource client credentials — distinct from main client
    assert body["client_id"] == ["xaa-client-main-at-res_abc"]
    assert body["client_secret"] == ["xaa-secret-res"]


@pytest.mark.asyncio
async def test_exchange_id_jag_400_with_non_json_body_still_raises(client):
    with respx.mock:
        respx.post(f"{AUTH}/token").mock(
            return_value=httpx.Response(400, text="Bad Request")
        )
        with pytest.raises(XAADevError) as excinfo:
            await client.exchange_id_jag_for_access_token(id_jag="x")

    assert excinfo.value.status_code == 400
    assert excinfo.value.error_code == ""
    assert "Bad Request" in excinfo.value.response_body
