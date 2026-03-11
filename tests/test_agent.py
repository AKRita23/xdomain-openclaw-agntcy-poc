"""Tests for the OpenClaw agent orchestrator."""
import pytest
from unittest.mock import AsyncMock, patch
from agent.openclaw_agent import OpenClawAgent
from agent.config import AgentConfig
from agent.task_context import TaskContext


@pytest.fixture
def agent():
    config = AgentConfig(
        agent_id="test-agent-001",
        identity_service_url="http://localhost:8080",
        auth0_domain="dev-test.us.auth0.com",
        auth0_client_id="test-client-id",
        auth0_client_secret="test-client-secret",
        delegating_user="sarah@example.com",
    )
    return OpenClawAgent(config)


@pytest.mark.asyncio
async def test_execute_task(agent):
    # Mock the Auth0 token exchange to avoid real HTTP calls
    mock_response = {
        "access_token": "test-access-token-placeholder",
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "contacts.read",
    }
    with patch.object(agent.xaa_client, "exchange_token",
                      new_callable=AsyncMock, return_value=mock_response):
        result = await agent.execute_task("Test cross-domain task")
    assert "task_id" in result
    assert "delegation_chain" in result
    assert "results" in result
    assert set(result["results"].keys()) == {"salesforce", "gcal", "slack"}


def test_task_context_delegation():
    ctx = TaskContext(
        task_description="test",
        delegating_user="sarah@example.com",
        agent_id="test-agent",
    )
    ctx.add_delegation(
        delegator="test-agent",
        delegatee="salesforce",
        auth_domain="salesforce.com",
        scopes=["contacts.read"],
    )
    chain = ctx.get_chain_summary()
    assert len(chain) == 1
    assert chain[0]["domain"] == "salesforce.com"
