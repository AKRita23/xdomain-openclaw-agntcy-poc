"""Tests for AGNTCY TBAC middleware."""
from datetime import datetime, timedelta, timezone

import pytest
from unittest.mock import AsyncMock, patch
from middleware.agntcy_tbac import IdentityServiceMCPMiddleware, TBACViolation


@pytest.fixture
def middleware():
    mw = IdentityServiceMCPMiddleware("http://localhost:8080")
    # Mock the verifier so tests don't require a real JWKS endpoint
    mw.verifier.verify_badge = AsyncMock(
        return_value={"valid": True, "badge_id": "badge-test"}
    )
    return mw


def _make_badge(scopes=None, capabilities=None, issuance_date=None):
    badge = {
        "badge_id": "badge-test",
        "jwt": "eyJ.test.token",
        "task_scopes": scopes or [],
    }
    if capabilities is not None:
        badge["capabilities"] = capabilities
    if issuance_date is not None:
        badge["issuanceDate"] = issuance_date
    return badge


def _make_xaa_token(task=None):
    token = {"access_token": "xaa-test-token", "token_type": "Bearer"}
    if task is not None:
        token["task"] = task
    return token


@pytest.mark.asyncio
async def test_enforce_allows_valid_request(middleware):
    await middleware.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_scope_escalation(middleware):
    badge = _make_badge(scopes=["weather:read"])
    with pytest.raises(TBACViolation, match="Scope escalation"):
        await middleware.enforce(
            badge=badge,
            target_server="weather",
            requested_scopes=["weather:read", "weather:admin"],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_blocks_missing_token(middleware):
    with pytest.raises(TBACViolation, match="Missing XAA"):
        await middleware.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token={},
        )


@pytest.mark.asyncio
async def test_enforce_blocks_invalid_badge():
    """When badge verification fails, enforce raises TBACViolation."""
    mw = IdentityServiceMCPMiddleware("http://localhost:8080")
    mw.verifier.verify_badge = AsyncMock(
        return_value={"valid": False, "reason": "Badge JWT has expired"}
    )
    with pytest.raises(TBACViolation, match="Badge verification failed"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


# --- Task context validation tests ---


@pytest.mark.asyncio
async def test_enforce_allows_correct_task(middleware):
    """When task claim matches, enforce passes."""
    await middleware.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(task="weather_slack_notification"),
    )


@pytest.mark.asyncio
async def test_enforce_allows_missing_task(middleware):
    """When task claim is absent, enforce passes (no constraint)."""
    await middleware.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_task_mismatch(middleware):
    with pytest.raises(TBACViolation, match="Task mismatch"):
        await middleware.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(task="exfiltrate_data"),
        )


# --- Domain validation tests ---


@pytest.mark.asyncio
async def test_enforce_allows_authorized_domain(middleware):
    caps = [{"domain": "weather"}, {"domain": "slack"}]
    await middleware.enforce(
        badge=_make_badge(capabilities=caps),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_allows_empty_capabilities(middleware):
    """Empty capabilities list = open badge model, no domain restriction."""
    await middleware.enforce(
        badge=_make_badge(capabilities=[]),
        target_server="anything",
        requested_scopes=[],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_unauthorized_domain(middleware):
    caps = [{"domain": "weather"}]
    with pytest.raises(TBACViolation, match="Domain .* not authorized"):
        await middleware.enforce(
            badge=_make_badge(capabilities=caps),
            target_server="slack",
            requested_scopes=[],
            xaa_token=_make_xaa_token(),
        )


# --- Badge TTL validation tests ---


@pytest.mark.asyncio
async def test_enforce_allows_fresh_badge(middleware):
    fresh = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    await middleware.enforce(
        badge=_make_badge(issuance_date=fresh),
        target_server="weather",
        requested_scopes=[],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_expired_badge(middleware):
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    with pytest.raises(TBACViolation, match="exceeded 24h TTL"):
        await middleware.enforce(
            badge=_make_badge(issuance_date=old),
            target_server="weather",
            requested_scopes=[],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_allows_no_issuance_date(middleware):
    """No issuanceDate = skip TTL check."""
    await middleware.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=[],
        xaa_token=_make_xaa_token(),
    )
