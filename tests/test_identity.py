"""Tests for identity badge issuance, verification, and Okta XAA."""
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
async def test_okta_exchange_success(xaa_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "real-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }
    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_response
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await xaa_client.exchange_token(
            subject_token="badge-jwt",
            target_audience="salesforce.com",
            scopes=["contacts.read"],
        )
    assert result["access_token"] == "real-token"


@pytest.mark.asyncio
async def test_okta_exchange_falls_back_on_unsupported_grant(xaa_client):
    """When RFC 8693 fails with unsupported_grant_type, falls back to client_credentials."""
    rfc8693_response = MagicMock()
    rfc8693_response.status_code = 403
    rfc8693_response.json.return_value = {"error": "unsupported_grant_type"}

    cc_response = MagicMock()
    cc_response.status_code = 200
    cc_response.json.return_value = {
        "access_token": "cc-fallback-token",
        "token_type": "Bearer",
        "expires_in": 3600,
    }

    with patch("identity.okta_xaa.httpx.AsyncClient") as mock_client_cls:
        mock_client = AsyncMock()
        mock_client.post.side_effect = [rfc8693_response, cc_response]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await xaa_client.exchange_token(
            subject_token="badge-jwt",
            target_audience="salesforce.com",
            scopes=["contacts.read"],
        )
    assert result["access_token"] == "cc-fallback-token"
    assert result["_badge_jwt"] == "badge-jwt"


@pytest.mark.asyncio
async def test_okta_exchange_raises_on_other_errors(xaa_client):
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
                target_audience="salesforce.com",
            )
