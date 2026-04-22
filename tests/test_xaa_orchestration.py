"""Integration-style tests for the six-step XAA flow orchestrator.

Mocks every layer boundary (AGNTCY badge issuer + verifier, Okta, resource
auth server, TBAC middleware, Weather MCP) and asserts call order, data
flow between layers, error propagation per step, and cache behavior.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent.config import AgentConfig, MCPServerConfig
from agent.xaa_orchestrator import (
    TOTAL_STEPS,
    XAAFlowError,
    XAAOrchestrator,
)
from identity.resource_exchange import CachedTokenStore, ResourceAccessToken
from middleware.agntcy_tbac import TBACViolation


@pytest.fixture
def badge():
    return {
        "badge_id": "badge-test-001",
        "agent_id": "openclaw-agent-001",
        "delegating_user": "sarah@example.com",
        "issuer_did": "did:web:example.com:issuer",
        "jwt": "eyJ.badge.jwt",
        "issued_at": "2026-04-19T00:00:00Z",
        "task_scopes": ["weather:read"],
    }


@pytest.fixture
def access_token():
    return ResourceAccessToken(
        access_token="minted.access.token",
        token_type="Bearer",
        expires_in=3600,
        scope="weather:read",
        expires_at=int(time.time()) + 3600,
    )


@pytest.fixture
def orchestrator(badge, access_token, monkeypatch):
    """XAAOrchestrator with every collaborator stubbed."""
    cfg = AgentConfig(
        identity_service_url="http://identity.test",
        okta_domain="dev.okta.test",
        okta_client_id="client-abc",
        mcp_servers={
            "weather": MCPServerConfig(
                name="weather",
                url="http://weather.test",
                auth_domain="api.open-meteo.com",
                scopes=["weather:read"],
            ),
        },
    )

    badge_issuer = MagicMock()
    badge_issuer.issue_badge = AsyncMock(return_value=badge)

    badge_verifier = MagicMock()
    badge_verifier.verify_badge = AsyncMock(
        return_value={
            "valid": True,
            "badge_id": badge["badge_id"],
            "capabilities": ["weather:read"],
            "delegating_user": badge["delegating_user"],
            "issuer": "did:web:example.com:issuer",
            "issuance_date": "2026-04-19T00:00:00Z",
        }
    )

    xaa_client = MagicMock()
    xaa_client.exchange_token = AsyncMock(
        return_value={
            "access_token": "okta.id-jag.jwt",
            "token_type": "Bearer",
            "expires_in": 300,
        }
    )

    middleware = MagicMock()
    middleware.enforce = AsyncMock(return_value=None)

    weather_client = MagicMock()
    weather_client.config = cfg.mcp_servers["weather"]
    weather_client.call = AsyncMock(
        return_value={
            "tool": "get_current_weather",
            "result": {
                "location": "Austin, TX",
                "temperature_c": 22.0,
                "condition": "partly cloudy",
            },
        }
    )

    monkeypatch.setattr(
        "agent.xaa_orchestrator.exchange_id_jag_for_access_token",
        lambda id_jag, client_id, scope: access_token,
    )

    return XAAOrchestrator(
        config=cfg,
        badge_issuer=badge_issuer,
        badge_verifier=badge_verifier,
        xaa_client=xaa_client,
        middleware=middleware,
        weather_client=weather_client,
        token_cache=CachedTokenStore(),
    )


@pytest.mark.asyncio
async def test_full_flow_runs_all_six_steps_in_order(orchestrator, badge, access_token):
    result = await orchestrator.execute(
        task_name="weather_slack_notification",
        target_audience="api.open-meteo.com",
        scopes=["weather:read"],
        subject="sarah@example.com",
    )

    # Step 1 — badge issued for the right subject
    orchestrator.badge_issuer.issue_badge.assert_awaited_once()
    issue_kwargs = orchestrator.badge_issuer.issue_badge.await_args.kwargs
    assert issue_kwargs["delegating_user"] == "sarah@example.com"
    assert issue_kwargs["task_scopes"] == ["weather:read"]

    # Step 2 — verifier received the exact badge from step 1
    orchestrator.badge_verifier.verify_badge.assert_awaited_once_with(badge)

    # Step 3 — Okta exchange carried the badge JWT through
    orchestrator.xaa_client.exchange_token.assert_awaited_once()
    xaa_kwargs = orchestrator.xaa_client.exchange_token.await_args.kwargs
    assert xaa_kwargs["subject_token"] == badge["jwt"]
    assert xaa_kwargs["badge_jwt"] == badge["jwt"]
    assert xaa_kwargs["target_audience"] == "api.open-meteo.com"
    assert xaa_kwargs["scopes"] == ["weather:read"]

    # Step 5 — TBAC got the post-exchange access token
    orchestrator.middleware.enforce.assert_awaited_once()
    tbac_kwargs = orchestrator.middleware.enforce.await_args.kwargs
    assert tbac_kwargs["badge"] == badge
    assert tbac_kwargs["target_server"] == "api.open-meteo.com"
    assert tbac_kwargs["requested_scopes"] == ["weather:read"]
    assert tbac_kwargs["xaa_token"]["access_token"] == access_token.access_token
    assert tbac_kwargs["xaa_token"]["task"] == "weather_slack_notification"

    # Step 6 — MCP call used the resource-auth-server access token
    orchestrator.weather_client.call.assert_awaited_once_with(
        token=access_token.access_token
    )

    # Structured result reflects the chain
    assert result.task_name == "weather_slack_notification"
    assert result.badge_id == badge["badge_id"]
    assert result.id_jag_expires_in == 300
    assert result.access_token_scope == "weather:read"
    assert result.access_token_expires_in == 3600
    assert result.cached is False
    assert result.mcp_result["result"]["location"] == "Austin, TX"


@pytest.mark.asyncio
async def test_second_call_uses_cached_access_token(orchestrator):
    kwargs = dict(
        task_name="weather_slack_notification",
        target_audience="api.open-meteo.com",
        scopes=["weather:read"],
        subject="sarah@example.com",
    )
    first = await orchestrator.execute(**kwargs)
    second = await orchestrator.execute(**kwargs)

    assert first.cached is False
    assert second.cached is True
    # Okta and resource-exchange are NOT invoked on the cached path
    orchestrator.xaa_client.exchange_token.assert_awaited_once()
    # Badge issue + verify + TBAC + MCP still run both times
    assert orchestrator.badge_issuer.issue_badge.await_count == 2
    assert orchestrator.badge_verifier.verify_badge.await_count == 2
    assert orchestrator.middleware.enforce.await_count == 2
    assert orchestrator.weather_client.call.await_count == 2


@pytest.mark.asyncio
async def test_distinct_subject_does_not_share_cache(orchestrator):
    base = dict(
        task_name="weather_slack_notification",
        target_audience="api.open-meteo.com",
        scopes=["weather:read"],
    )
    await orchestrator.execute(subject="sarah@example.com", **base)
    await orchestrator.execute(subject="bob@example.com", **base)

    # Different subject → cache miss → second Okta exchange
    assert orchestrator.xaa_client.exchange_token.await_count == 2


@pytest.mark.asyncio
async def test_badge_verification_failure_halts_at_step_2(orchestrator):
    orchestrator.badge_verifier.verify_badge = AsyncMock(
        return_value={"valid": False, "reason": "invalid signature"}
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 2
    assert "invalid signature" in excinfo.value.reason
    # Downstream steps never ran
    orchestrator.xaa_client.exchange_token.assert_not_awaited()
    orchestrator.middleware.enforce.assert_not_awaited()
    orchestrator.weather_client.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_okta_exchange_failure_surfaces_as_step_3(orchestrator):
    orchestrator.xaa_client.exchange_token = AsyncMock(
        side_effect=RuntimeError("Okta returned 401")
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 3
    assert "401" in excinfo.value.reason
    orchestrator.middleware.enforce.assert_not_awaited()
    orchestrator.weather_client.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_okta_returns_empty_token_fails_at_step_3(orchestrator):
    orchestrator.xaa_client.exchange_token = AsyncMock(
        return_value={"access_token": "", "expires_in": 0}
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 3


@pytest.mark.asyncio
async def test_resource_exchange_failure_surfaces_as_step_4(
    orchestrator, monkeypatch
):
    from identity.resource_exchange import ResourceExchangeError

    def boom(id_jag, client_id, scope):
        raise ResourceExchangeError(
            error="invalid_grant",
            description="expired assertion",
            status_code=400,
        )

    monkeypatch.setattr(
        "agent.xaa_orchestrator.exchange_id_jag_for_access_token", boom
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 4
    assert "expired assertion" in excinfo.value.reason
    orchestrator.middleware.enforce.assert_not_awaited()
    orchestrator.weather_client.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_tbac_violation_surfaces_as_step_5(orchestrator):
    orchestrator.middleware.enforce = AsyncMock(
        side_effect=TBACViolation(reason="scope escalation")
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 5
    assert "scope escalation" in excinfo.value.reason
    orchestrator.weather_client.call.assert_not_awaited()


@pytest.mark.asyncio
async def test_mcp_failure_surfaces_as_step_6(orchestrator):
    orchestrator.weather_client.call = AsyncMock(
        side_effect=RuntimeError("MCP connection refused")
    )

    with pytest.raises(XAAFlowError) as excinfo:
        await orchestrator.execute(
            task_name="t",
            target_audience="api.open-meteo.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 6
    assert "refused" in excinfo.value.reason


def test_xaaflow_error_carries_step_within_total():
    err = XAAFlowError(step=4, reason="boom")
    assert 1 <= err.step <= TOTAL_STEPS
    assert "step 4" in str(err)


# --------------------------------------------------------------------------- xaa.dev path


@pytest.fixture
def xaa_dev_orchestrator(badge, monkeypatch):
    """XAAOrchestrator wired with a mocked :class:`XAADevClient`.

    Covers the USE_XAA_DEV=true branch: Steps 3 and 4 go through xaa.dev
    (token-exchange + jwt-bearer) instead of the Okta path.
    """
    cfg = AgentConfig(
        identity_service_url="http://identity.test",
        mcp_servers={
            "weather": MCPServerConfig(
                name="weather", url="http://weather.test",
                auth_domain="api.open-meteo.com", scopes=["weather:read"],
            ),
        },
    )

    badge_issuer = MagicMock()
    badge_issuer.issue_badge = AsyncMock(return_value=badge)

    badge_verifier = MagicMock()
    badge_verifier.verify_badge = AsyncMock(return_value={
        "valid": True, "badge_id": badge["badge_id"],
        "capabilities": ["weather:read"],
        "delegating_user": badge["delegating_user"],
        "issuer": "did:web:example.com:issuer",
        "issuance_date": "2026-04-19T00:00:00Z",
    })

    # The Okta client must NOT be invoked on this path.
    xaa_client = MagicMock()
    xaa_client.exchange_token = AsyncMock(side_effect=AssertionError(
        "OktaXAAClient.exchange_token should not be called on the xaa.dev path"
    ))

    middleware = MagicMock()
    middleware.enforce = AsyncMock(return_value=None)

    weather_client = MagicMock()
    weather_client.config = cfg.mcp_servers["weather"]
    weather_client.call = AsyncMock(return_value={
        "tool": "get_current_weather",
        "result": {"location": "Austin, TX"},
    })

    xaa_dev_client = MagicMock()
    xaa_dev_client.config = MagicMock()
    xaa_dev_client.config.auth_server_url = "https://auth.resource.xaa.dev"
    xaa_dev_client.config.resource_audience = "http://weather-slack-resources.com"
    xaa_dev_client.exchange_id_token_for_id_jag = AsyncMock(return_value={
        "access_token": "xaa.dev.id-jag",
        "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
        "token_type": "Bearer",
        "expires_in": 300,
    })
    xaa_dev_client.exchange_id_jag_for_access_token = AsyncMock(return_value={
        "access_token": "xaa.dev.access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "openid email",
    })

    monkeypatch.setenv("XAA_ID_TOKEN", "sarah.id.token")

    return XAAOrchestrator(
        config=cfg,
        badge_issuer=badge_issuer,
        badge_verifier=badge_verifier,
        xaa_client=xaa_client,
        middleware=middleware,
        weather_client=weather_client,
        token_cache=CachedTokenStore(),
        xaa_dev_client=xaa_dev_client,
    )


@pytest.mark.asyncio
async def test_xaa_dev_path_runs_token_exchange_and_jwt_bearer(
    xaa_dev_orchestrator, badge,
):
    result = await xaa_dev_orchestrator.execute(
        task_name="weather_slack_notification",
        target_audience="http://weather-slack-resources.com",
        scopes=["weather:read"],
        subject="sarah@example.com",
    )

    # Steps 3 + 4: both xaa.dev endpoints invoked, Okta client untouched
    xaa_dev_orchestrator.xaa_dev_client.exchange_id_token_for_id_jag \
        .assert_awaited_once_with("sarah.id.token")
    xaa_dev_orchestrator.xaa_dev_client.exchange_id_jag_for_access_token \
        .assert_awaited_once_with("xaa.dev.id-jag")
    xaa_dev_orchestrator.xaa_client.exchange_token.assert_not_called()

    # Step 6: MCP call uses the xaa.dev access token
    xaa_dev_orchestrator.weather_client.call.assert_awaited_once_with(
        token="xaa.dev.access_token",
    )
    assert result.access_token_scope == "openid email"
    assert result.id_jag_expires_in == 300


@pytest.mark.asyncio
async def test_xaa_dev_path_requires_id_token_env_var(
    xaa_dev_orchestrator, monkeypatch,
):
    monkeypatch.delenv("XAA_ID_TOKEN", raising=False)
    with pytest.raises(XAAFlowError) as excinfo:
        await xaa_dev_orchestrator.execute(
            task_name="t",
            target_audience="http://weather-slack-resources.com",
            scopes=["weather:read"],
            subject="sarah@example.com",
        )
    assert excinfo.value.step == 3
    assert "XAA_ID_TOKEN" in excinfo.value.reason
    assert "get_xaa_id_token" in excinfo.value.reason
    xaa_dev_orchestrator.xaa_dev_client.exchange_id_token_for_id_jag \
        .assert_not_called()
