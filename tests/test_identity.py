"""Tests for identity badge issuance, verification, and Okta XAA (ID-JAG)."""
import httpx
import pytest
import respx
from unittest.mock import AsyncMock, patch, MagicMock
from identity.badge_issuer import BadgeIssuer
from identity.badge_verifier import BadgeVerifier
from identity.okta_xaa import OktaXAAClient, TokenExchangeError


@pytest.fixture
def issuer():
    return BadgeIssuer("http://localhost:8080")


@pytest.fixture
def verifier():
    return BadgeVerifier("http://localhost:8080")


@pytest.fixture
def xaa_client():
    return OktaXAAClient(
        domain="dev-test.okta.com",
        client_id="test-client-id",
        client_secret="test-client-secret",
        auth_server_id="default",
    )


@pytest.mark.asyncio
async def test_issue_badge(issuer, monkeypatch):
    well_known = "http://identity.test/v1alpha1/vc/AGNTCY-x/.well-known/vcs.json"
    monkeypatch.setenv("AGNTCY_BADGE_WELL_KNOWN", well_known)
    monkeypatch.setenv("AGNTCY_BADGE_ID", "badge-test-001")

    with respx.mock:
        respx.get(well_known).mock(return_value=httpx.Response(200, json={
            "vcs": [{"value": "eyJ.fake.jwt"}],
        }))
        badge = await issuer.issue_badge(
            agent_id="test-agent",
            delegating_user="sarah@example.com",
            issuer_did="did:example:issuer",
        )
    assert badge["agent_id"] == "test-agent"
    assert badge["delegating_user"] == "sarah@example.com"
    assert badge["jwt"] == "eyJ.fake.jwt"


@pytest.mark.asyncio
async def test_verify_valid_badge(verifier):
    """Valid badge verified via Identity Node REST API."""
    verify_resp = MagicMock()
    verify_resp.status_code = 200
    verify_resp.json.return_value = {
        "status": True,
        "document": {
            "issuer": "did:web:example.com:issuer",
            "issuanceDate": "2026-01-01T00:00:00Z",
            "content": {
                "id": "badge-test",
                "badge": '{"capabilities": ["weather:read"], "delegating_user": "sarah@example.com"}',
            },
        },
        "errors": [],
    }

    with patch("identity.badge_verifier.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = verify_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        badge = {"badge_id": "badge-test", "jwt": "eyJ.test.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is True
    assert result["badge_id"] == "badge-test"
    assert result["capabilities"] == ["weather:read"]


@pytest.mark.asyncio
async def test_verify_invalid_badge_missing_fields(verifier):
    result = await verifier.verify_badge({})
    assert result["valid"] is False
    assert "Missing" in result["reason"]


@pytest.mark.asyncio
async def test_verify_expired_badge(verifier):
    """Expired badge JWT is rejected by Identity Node."""
    verify_resp = MagicMock()
    verify_resp.status_code = 200
    verify_resp.json.return_value = {
        "status": False,
        "document": {},
        "errors": ["credential has expired"],
    }

    with patch("identity.badge_verifier.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = verify_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        badge = {"badge_id": "badge-test", "jwt": "eyJ.expired.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "expired" in result["reason"].lower()


@pytest.mark.asyncio
async def test_verify_bad_signature_badge(verifier):
    """Badge with invalid signature is rejected by Identity Node."""
    verify_resp = MagicMock()
    verify_resp.status_code = 200
    verify_resp.json.return_value = {
        "status": False,
        "document": {},
        "errors": ["invalid signature on credential"],
    }

    with patch("identity.badge_verifier.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = verify_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        badge = {"badge_id": "badge-test", "jwt": "eyJ.badsig.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "signature" in result["reason"].lower()


@pytest.mark.asyncio
async def test_verify_jwks_unavailable(verifier):
    """When Identity Node is unreachable, badge is rejected."""
    import httpx as _httpx

    with patch("identity.badge_verifier.httpx.AsyncClient") as mock_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = _httpx.ConnectError("Connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_client

        badge = {"badge_id": "badge-test", "jwt": "eyJ.test.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "failed" in result["reason"].lower()


def test_okta_client_token_endpoint(xaa_client):
    # Path-B refactor (commit 2739b1e) moved the token endpoint to Okta's
    # org auth server (/oauth2/v1/token) so the ID-JAG flow uses the
    # tenant's CrossAppAccess-enabled root endpoint rather than a
    # per-app auth-server URL.
    assert xaa_client.token_endpoint == "https://dev-test.okta.com/oauth2/v1/token"


def test_validate_token_response_rejects_missing_access_token():
    """Token response without access_token is rejected."""
    with pytest.raises(TokenExchangeError, match="missing access_token"):
        OktaXAAClient._validate_token_response(
            {"token_type": "Bearer", "expires_in": 3600},
            "api.open-meteo.com",
        )


def test_validate_token_response_rejects_zero_expiry():
    """Token response with zero expires_in is rejected."""
    with pytest.raises(TokenExchangeError, match="expires_in"):
        OktaXAAClient._validate_token_response(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": 0},
            "api.open-meteo.com",
        )


def test_validate_token_response_rejects_negative_expiry():
    """Token response with negative expires_in is rejected."""
    with pytest.raises(TokenExchangeError, match="expires_in"):
        OktaXAAClient._validate_token_response(
            {"access_token": "tok", "token_type": "Bearer", "expires_in": -1},
            "api.open-meteo.com",
        )


def test_validate_token_response_accepts_opaque_token():
    """Opaque (non-JWT) tokens pass validation when expiry is valid."""
    OktaXAAClient._validate_token_response(
        {"access_token": "opaque-token-value", "token_type": "Bearer", "expires_in": 3600},
        "api.open-meteo.com",
    )


@pytest.fixture
def xaa_client_for_weather():
    """OktaXAAClient configured for the weather audience.

    The Path-B refactor (commit 2739b1e) made ``exchange_token`` resolve
    the Org-2 audience via ``_resolve_org2_target``, which requires the
    client to know either the scope-to-resource mapping or an explicit
    weather audience. The default ``xaa_client`` fixture above leaves
    these blank for the unit tests that don't exercise the full flow;
    this fixture wires them in for the round-trip test below.
    """
    return OktaXAAClient(
        domain="dev-test.okta.com",
        client_id="test-client-id",
        client_secret="test-client-secret",
        org2_domain="dev-test.okta.com",
        weather_auth_server_id="ausweather",
        weather_audience="http://localhost:5001",
    )


@pytest.mark.asyncio
async def test_okta_id_jag_exchange_success(xaa_client_for_weather, monkeypatch):
    """Post-Path-B contract: ``exchange_token`` POSTs Sarah's ID token to
    Okta's org token endpoint and returns the ID-JAG. The resource auth
    server (a separate module) is what mints the scoped access token
    from that ID-JAG — not exercised here.
    """
    # SARAH_ACCESS_TOKEN avoids the AWS Secrets Manager path in load_sarah_token.
    monkeypatch.setenv("SARAH_ACCESS_TOKEN", "sarah-id-token-jwt")

    id_jag_response = MagicMock()
    id_jag_response.status_code = 200
    id_jag_response.json.return_value = {
        "access_token": "id-jag-assertion-jwt",
        "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
        "token_type": "Bearer",
        "expires_in": 300,
    }

    captured: dict = {}

    class _FakeAsyncClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return None
        async def post(self, url, data=None):
            captured["url"] = url
            captured["data"] = dict(data or {})
            return id_jag_response

    with patch("identity.okta_xaa.httpx.AsyncClient", _FakeAsyncClient), \
         patch.object(OktaXAAClient, "_validate_token_response"):
        result = await xaa_client_for_weather.exchange_token(
            subject_token="ignored",  # current impl uses load_sarah_token()
            target_audience="http://localhost:5001",
            scopes=["weather.read"],
            badge_jwt="badge-jwt-value",
        )

    # Single POST to Okta's org token endpoint, ID-JAG returned.
    assert result["access_token"] == "id-jag-assertion-jwt"
    assert (
        result["issued_token_type"]
        == "urn:ietf:params:oauth:token-type:id-jag"
    )
    assert captured["url"] == "https://dev-test.okta.com/oauth2/v1/token"
    # Phase-1 fix #5: badge_jwt is wired through as actor_token + actor_token_type.
    assert captured["data"]["actor_token"] == "badge-jwt-value"
    assert (
        captured["data"]["actor_token_type"]
        == "urn:ietf:params:oauth:token-type:jwt"
    )
    # And as token-exchange parameters
    assert (
        captured["data"]["grant_type"]
        == "urn:ietf:params:oauth:grant-type:token-exchange"
    )
    assert (
        captured["data"]["requested_token_type"]
        == "urn:ietf:params:oauth:token-type:id-jag"
    )
    assert captured["data"]["subject_token"] == "sarah-id-token-jwt"


@pytest.mark.asyncio
async def test_okta_id_jag_exchange_error_on_jag_request(xaa_client):
    """When the first POST (ID-JAG request) fails, should raise TokenExchangeError."""
    error_response = MagicMock()
    error_response.status_code = 401
    error_response.json.return_value = {"error": "invalid_client"}

    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = error_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with pytest.raises(TokenExchangeError):
            await xaa_client.exchange_token(
                subject_token="badge-jwt",
                target_audience="api.open-meteo.com",
                scopes=["weather:read"],
                badge_jwt="badge-jwt",
            )


@pytest.mark.asyncio
async def test_okta_id_jag_exchange_error_on_token_exchange(xaa_client):
    """When ID-JAG succeeds but token exchange fails, should raise TokenExchangeError."""
    id_jag_response = MagicMock()
    id_jag_response.status_code = 200
    id_jag_response.json.return_value = {
        "access_token": "id-jag-assertion-jwt",
        "token_type": "Bearer",
        "expires_in": 300,
    }

    error_response = MagicMock()
    error_response.status_code = 401
    error_response.json.return_value = {"error": "invalid_grant"}

    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = [id_jag_response, error_response]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        with pytest.raises(TokenExchangeError):
            await xaa_client.exchange_token(
                subject_token="badge-jwt",
                target_audience="api.open-meteo.com",
                scopes=["weather:read"],
                badge_jwt="badge-jwt",
            )


def test_load_secret_fallback():
    """When boto3 is unavailable, returns empty dict."""
    from identity.secrets import load_secret
    result = load_secret("nonexistent-secret")
    assert result == {}
