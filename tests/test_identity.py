"""Tests for identity badge issuance, verification, and Okta XAA (ID-JAG)."""
import pytest
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
    badge = {
        "badge_id": "badge-test",
        "jwt": "eyJ.test.token",
    }
    result = await verifier.verify_badge(badge)
    assert result["valid"] is True


@pytest.mark.asyncio
async def test_verify_invalid_badge(verifier):
    result = await verifier.verify_badge({})
    assert result["valid"] is False


def test_okta_client_token_endpoint(xaa_client):
    assert xaa_client.token_endpoint == "https://dev-test.okta.com/oauth2/default/v1/token"


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

    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls:
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
