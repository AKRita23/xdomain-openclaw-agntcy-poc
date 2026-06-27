"""Tests for AGNTCY TBAC middleware (Phase-1 hardened contract).

The Phase-1 hardening intentionally broke three behaviors that previously
made these tests pass; the tests below have been updated to assert the
new contract:

  * Scope subset is now computed from the VERIFIER's ``capabilities``
    (verified result), never the caller dict's ``task_scopes``.
  * Empty / missing verified capabilities now DENY (was: open badge).
  * TTL gate now reads ``issuance_date`` (snake_case) from the verifier
    result; missing now DENIES (was: skipped).

The fixture below lets each test stub the verifier's return value to
exercise specific paths. Where the old behavior was the bug (fail-open
on empty caps / missing issuance), the test is inverted with an explicit
comment so the contract reversal is documented in-place.
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest
from unittest.mock import AsyncMock

from middleware.agntcy_tbac import IdentityServiceMCPMiddleware, TBACViolation


def _fresh_iso() -> str:
    """ISO-8601 timestamp 1h in the past — well within the 24h TTL."""
    return (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _make_verification(
    *,
    valid: bool = True,
    capabilities: Optional[List[Any]] = None,
    issuance_date: Optional[str] = None,
    delegating_user: str = "sarah@example.com",
    agent_id: str = "openclaw-agent-001",
    badge_id: str = "badge-test",
) -> Dict[str, Any]:
    """Build a verifier-result dict in the shape :class:`BadgeVerifier` returns."""
    if not valid:
        return {"valid": False, "reason": "Badge JWT has expired"}
    return {
        "valid": True,
        "badge_id": badge_id,
        "capabilities": (
            capabilities if capabilities is not None
            else ["weather:read"]
        ),
        "delegating_user": delegating_user,
        "agent_id": agent_id,
        "issuer": "did:web:example.com:issuer",
        "issuance_date": issuance_date or _fresh_iso(),
    }


def _mw_with(verification: Dict[str, Any]) -> IdentityServiceMCPMiddleware:
    mw = IdentityServiceMCPMiddleware("http://localhost:8080")
    mw.verifier.verify_badge = AsyncMock(return_value=verification)
    return mw


def _make_badge() -> Dict[str, Any]:
    """Caller-supplied badge dict — task_scopes here MUST be ignored."""
    return {
        "badge_id": "badge-test",
        "jwt": "eyJ.test.token",
        "task_scopes": ["weather:read", "totally:bogus:scope"],  # noise
    }


def _make_xaa_token(task: Optional[str] = None) -> Dict[str, Any]:
    token = {"access_token": "xaa-test-token", "token_type": "Bearer"}
    if task is not None:
        token["task"] = task
    return token


# --------------------------------------------------------------------------- happy path


@pytest.mark.asyncio
async def test_enforce_allows_valid_request():
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


# --------------------------------------------------------------------------- scope subset


@pytest.mark.asyncio
async def test_enforce_blocks_scope_escalation():
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    with pytest.raises(TBACViolation, match="Scope escalation"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read", "weather:admin"],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_ignores_caller_supplied_task_scopes():
    """Phase-1 fix #1: the caller's badge["task_scopes"] is untrusted.

    The badge dict claims ``totally:bogus:scope`` but the VERIFIED set
    only contains ``weather:read``. Requesting the bogus scope must DENY.
    """
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    with pytest.raises(TBACViolation, match="Scope escalation"):
        await mw.enforce(
            badge=_make_badge(),  # task_scopes includes "totally:bogus:scope"
            target_server="weather",
            requested_scopes=["totally:bogus:scope"],
            xaa_token=_make_xaa_token(),
        )


# --------------------------------------------------------------------------- empty caps deny


@pytest.mark.asyncio
async def test_enforce_denies_empty_verified_capabilities():
    """Phase-1 fix #2: was a fail-open ("open badge model"); now DENIES.

    A verified badge with no capabilities cannot authorize anything.
    """
    mw = _mw_with(_make_verification(capabilities=[]))
    with pytest.raises(TBACViolation, match="no authorized scopes"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="anything",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_denies_missing_capabilities_field():
    """Even if the verifier omits the key entirely, fail closed."""
    verification = {
        "valid": True, "badge_id": "x",
        "issuance_date": _fresh_iso(),
        # no "capabilities" key
    }
    mw = _mw_with(verification)
    with pytest.raises(TBACViolation, match="no authorized scopes"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


# --------------------------------------------------------------------------- xaa_token check


@pytest.mark.asyncio
async def test_enforce_blocks_missing_token():
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    with pytest.raises(TBACViolation, match="Missing XAA"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token={},
        )


# --------------------------------------------------------------------------- badge invalidity


@pytest.mark.asyncio
async def test_enforce_blocks_invalid_badge():
    mw = _mw_with(_make_verification(valid=False))
    with pytest.raises(TBACViolation, match="Badge verification failed"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


# --------------------------------------------------------------------------- task validation


@pytest.mark.asyncio
async def test_enforce_allows_correct_task():
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(task="weather_slack_notification"),
        expected_task="weather_slack_notification",
    )


@pytest.mark.asyncio
async def test_enforce_blocks_task_mismatch():
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    with pytest.raises(TBACViolation, match="Task mismatch"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(task="exfiltrate_data"),
            expected_task="weather_slack_notification",
        )


@pytest.mark.asyncio
async def test_enforce_blocks_missing_task_when_expected():
    """When expected_task is set, a missing xaa_token.task must DENY."""
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    with pytest.raises(TBACViolation, match="Task mismatch"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),  # no task
            expected_task="weather_slack_notification",
        )


@pytest.mark.asyncio
async def test_enforce_no_task_constraint_when_expected_task_omitted():
    """If the caller doesn't pin a task, the middleware imposes none."""
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(task="whatever"),
    )


# --------------------------------------------------------------------------- domain validation


@pytest.mark.asyncio
async def test_enforce_allows_authorized_domain():
    caps = [
        {"scope": "weather:read", "domain": "weather"},
        {"scope": "slack:chat:write", "domain": "slack"},
    ]
    mw = _mw_with(_make_verification(capabilities=caps))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_unauthorized_domain():
    caps = [{"scope": "weather:read", "domain": "weather"}]
    mw = _mw_with(_make_verification(capabilities=caps))
    with pytest.raises(TBACViolation, match="Domain .* not authorized"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="slack",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


# --------------------------------------------------------------------------- TTL gate


@pytest.mark.asyncio
async def test_enforce_allows_fresh_badge():
    mw = _mw_with(_make_verification(
        capabilities=["weather:read"], issuance_date=_fresh_iso(),
    ))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
    )


@pytest.mark.asyncio
async def test_enforce_blocks_expired_badge():
    old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
    mw = _mw_with(_make_verification(
        capabilities=["weather:read"], issuance_date=old,
    ))
    with pytest.raises(TBACViolation, match="exceeded 24h TTL"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_denies_missing_issuance_date():
    """Phase-1 fix #3: was a fail-open (skipped TTL); now DENIES.

    The old code read ``badge["issuanceDate"]`` (camelCase) which never
    existed on the badge dict, so the TTL check was dead code. Now the
    verifier's ``issuance_date`` is required.
    """
    verification = {
        "valid": True, "badge_id": "x",
        "capabilities": ["weather:read"],
        # no issuance_date
    }
    mw = _mw_with(verification)
    with pytest.raises(TBACViolation, match="no issuance_date"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


@pytest.mark.asyncio
async def test_enforce_denies_unparseable_issuance_date():
    mw = _mw_with(_make_verification(
        capabilities=["weather:read"], issuance_date="not-a-date",
    ))
    with pytest.raises(TBACViolation, match="unparseable"):
        await mw.enforce(
            badge=_make_badge(),
            target_server="weather",
            requested_scopes=["weather:read"],
            xaa_token=_make_xaa_token(),
        )


# --------------------------------------------------------------------------- identity binding


@pytest.mark.asyncio
async def test_enforce_threads_expected_identity_to_verifier():
    """Phase-1 fix #4 plumbing: middleware must forward expected_* to verifier."""
    mw = _mw_with(_make_verification(capabilities=["weather:read"]))
    await mw.enforce(
        badge=_make_badge(),
        target_server="weather",
        requested_scopes=["weather:read"],
        xaa_token=_make_xaa_token(),
        expected_agent_id="openclaw-agent-001",
        expected_user="sarah@example.com",
    )
    mw.verifier.verify_badge.assert_awaited_once()
    kwargs = mw.verifier.verify_badge.await_args.kwargs
    assert kwargs["expected_agent_id"] == "openclaw-agent-001"
    assert kwargs["expected_user"] == "sarah@example.com"
