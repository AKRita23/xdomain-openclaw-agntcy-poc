"""Tests for MCP server client stubs."""
import pytest
from agent.config import MCPServerConfig
from mcp_servers.salesforce_mcp import SalesforceMCPClient
from mcp_servers.gcal_mcp import GCalMCPClient
from mcp_servers.slack_mcp import SlackMCPClient


@pytest.fixture
def sf_config():
    return MCPServerConfig(name="salesforce", url="http://localhost:9001",
                           auth_domain="salesforce.com", scopes=["contacts.read"])


@pytest.fixture
def gcal_config():
    return MCPServerConfig(name="gcal", url="http://localhost:9002",
                           auth_domain="googleapis.com", scopes=["calendar.events.read"])


@pytest.fixture
def slack_config():
    return MCPServerConfig(name="slack", url="http://localhost:9003",
                           auth_domain="slack.com", scopes=["chat.write"])


@pytest.mark.asyncio
async def test_salesforce_mcp(sf_config):
    client = SalesforceMCPClient(sf_config)
    result = await client.call(token="test-token-placeholder")
    assert result["tool"] == "salesforce.contacts.list"


@pytest.mark.asyncio
async def test_gcal_mcp(gcal_config):
    client = GCalMCPClient(gcal_config)
    result = await client.call(token="test-token-placeholder")
    assert result["tool"] == "gcal.events.list"


@pytest.mark.asyncio
async def test_slack_mcp(slack_config):
    client = SlackMCPClient(slack_config)
    result = await client.call(token="test-token-placeholder")
    assert result["tool"] == "slack.chat.postMessage"
