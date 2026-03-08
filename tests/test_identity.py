"""Tests for identity badge issuance and verification."""
import pytest
from identity.badge_issuer import BadgeIssuer
from identity.badge_verifier import BadgeVerifier


@pytest.fixture
def issuer():
    return BadgeIssuer("http://localhost:8080")


@pytest.fixture
def verifier():
    return BadgeVerifier("http://localhost:8080")


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
