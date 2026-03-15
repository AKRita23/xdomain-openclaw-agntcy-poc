"""Tests for AGNTCY TBAC middleware."""
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


def _make_badge(scopes=None):
    return {
        "badge_id": "badge-test",
        "jwt": "eyJ.test.token",
        "task_scopes": scopes or [],
    }


def _make_xaa_token():
    return {"access_token": "xaa-test-token", "token_type": "Bearer"}


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
