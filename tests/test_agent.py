"""Tests for the OpenClaw agent orchestrator."""
import httpx
import pytest
import respx
from unittest.mock import AsyncMock, patch
from agent.openclaw_agent import OpenClawAgent
from agent.config import AgentConfig
from agent.task_context import TaskContext


@pytest.fixture
def agent():
    config = AgentConfig(
        agent_id="test-agent-001",
        identity_service_url="http://localhost:8080",
        okta_domain="dev-test.us.okta.com",
        okta_client_id="test-client-id",
        okta_client_secret="test-client-secret",
        delegating_user="sarah@example.com",
    )
    return OpenClawAgent(config)


@pytest.mark.asyncio
async def test_execute_task(agent, monkeypatch):
    # Mock the Auth0 token exchange to avoid real HTTP calls
    mock_response = {
        "access_token": "test-access-token-placeholder",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "weather:read",
    }
    well_known = "http://identity.test/v1alpha1/vc/AGNTCY-x/.well-known/vcs.json"
    monkeypatch.setenv("AGNTCY_BADGE_WELL_KNOWN", well_known)
    with respx.mock, patch.object(
        agent.xaa_client, "exchange_token",
        new_callable=AsyncMock, return_value=mock_response,
    ):
        respx.get(well_known).mock(return_value=httpx.Response(200, json={
            "vcs": [{"value": "eyJ.fake.jwt"}],
        }))
        result = await agent.execute_task("Test cross-domain task")
    assert "task_id" in result
    assert "delegation_chain" in result
    assert "results" in result
    assert set(result["results"].keys()) == {"weather", "slack"}


def test_task_context_delegation():
    ctx = TaskContext(
        task_description="test",
        delegating_user="sarah@example.com",
        agent_id="test-agent",
    )
    ctx.add_delegation(
        delegator="test-agent",
        delegatee="weather",
        auth_domain="api.open-meteo.com",
        scopes=["weather:read"],
    )
    chain = ctx.get_chain_summary()
    assert len(chain) == 1
    assert chain[0]["domain"] == "api.open-meteo.com"
