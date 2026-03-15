"""Tests for identity badge issuance, verification, and Okta XAA (ID-JAG)."""
import pytest
import jwt as pyjwt
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
async def test_issue_badge(issuer):
    badge = await issuer.issue_badge(
        agent_id="test-agent",
        delegating_user="sarah@example.com",
        issuer_did="did:example:issuer",
    )
    assert badge["agent_id"] == "test-agent"
    assert badge["delegating_user"] == "sarah@example.com"
    assert "jwt" in badge


@pytest.mark.asyncio
async def test_verify_valid_badge(verifier):
    """Valid badge with mocked JWKS verification."""
    mock_key = MagicMock()
    mock_key.key = "test-public-key"
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.return_value = mock_key

    with patch.object(verifier, "_get_jwks_client", return_value=mock_jwks), \
         patch("identity.badge_verifier.jwt.decode") as mock_decode:
        mock_decode.return_value = {
            "sub": "agent-001",
            "iss": "did:web:example.com:issuer",
            "exp": 9999999999,
        }
        badge = {"badge_id": "badge-test", "jwt": "eyJ.test.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is True
    assert result["badge_id"] == "badge-test"
    assert "claims" in result


@pytest.mark.asyncio
async def test_verify_invalid_badge_missing_fields(verifier):
    result = await verifier.verify_badge({})
    assert result["valid"] is False
    assert "Missing" in result["reason"]


@pytest.mark.asyncio
async def test_verify_expired_badge(verifier):
    """Expired badge JWT is rejected."""
    mock_key = MagicMock()
    mock_key.key = "test-public-key"
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.return_value = mock_key

    with patch.object(verifier, "_get_jwks_client", return_value=mock_jwks), \
         patch("identity.badge_verifier.jwt.decode") as mock_decode:
        mock_decode.side_effect = pyjwt.ExpiredSignatureError("expired")
        badge = {"badge_id": "badge-test", "jwt": "eyJ.expired.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "expired" in result["reason"].lower()


@pytest.mark.asyncio
async def test_verify_bad_signature_badge(verifier):
    """Badge with invalid signature is rejected."""
    mock_key = MagicMock()
    mock_key.key = "test-public-key"
    mock_jwks = MagicMock()
    mock_jwks.get_signing_key_from_jwt.return_value = mock_key

    with patch.object(verifier, "_get_jwks_client", return_value=mock_jwks), \
         patch("identity.badge_verifier.jwt.decode") as mock_decode:
        mock_decode.side_effect = pyjwt.InvalidSignatureError("bad sig")
        badge = {"badge_id": "badge-test", "jwt": "eyJ.badsig.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "signature" in result["reason"].lower()


@pytest.mark.asyncio
async def test_verify_jwks_unavailable(verifier):
    """When JWKS endpoint is unreachable, badge is rejected."""
    with patch.object(verifier, "_get_jwks_client") as mock_get:
        mock_jwks = MagicMock()
        mock_jwks.get_signing_key_from_jwt.side_effect = pyjwt.PyJWKClientError("unreachable")
        mock_get.return_value = mock_jwks
        badge = {"badge_id": "badge-test", "jwt": "eyJ.test.token"}
        result = await verifier.verify_badge(badge)

    assert result["valid"] is False
    assert "JWKS" in result["reason"]


def test_okta_client_token_endpoint(xaa_client):
    assert xaa_client.token_endpoint == "https://dev-test.okta.com/oauth2/default/v1/token"


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


@pytest.mark.asyncio
async def test_okta_id_jag_exchange_success(xaa_client):
    """ID-JAG flow: first POST returns id_jag JWT, second returns access_token."""
    id_jag_response = MagicMock()
    id_jag_response.status_code = 200
    id_jag_response.json.return_value = {
        "access_token": "id-jag-assertion-jwt",
        "token_type": "Bearer",
        "expires_in": 300,
    }

    token_response = MagicMock()
    token_response.status_code = 200
    token_response.json.return_value = {
        "access_token": "scoped-access-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls, \
         patch.object(OktaXAAClient, "_validate_token_response"):
        mock_client = AsyncMock()
        mock_client.post.side_effect = [id_jag_response, token_response]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await xaa_client.exchange_token(
            subject_token="badge-jwt",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            badge_jwt="badge-jwt",
        )
    assert result["access_token"] == "scoped-access-token"


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
