"""Tests for MCP server clients (stub mode — no live MCP servers needed)."""
import pytest
from agent.config import MCPServerConfig
from mcp_servers.base import BaseMCPClient
from mcp_servers.salesforce_mcp import SalesforceMCPClient
from mcp_servers.gcal_mcp import GCalMCPClient
from mcp_servers.slack_mcp import SlackMCPClient


@pytest.fixture
def sf_config():
    return MCPServerConfig(name="salesforce", url="",
                           auth_domain="salesforce.com", scopes=["contacts.read"])


@pytest.fixture
def gcal_config():
    return MCPServerConfig(name="gcal", url="",
                           auth_domain="googleapis.com", scopes=["calendar.events.read"])


@pytest.fixture
def slack_config():
    return MCPServerConfig(name="slack", url="",
                           auth_domain="slack.com", scopes=["chat.write"])


@pytest.fixture
def live_config():
    """Config with a URL set — simulates live mode (won't actually connect)."""
    return MCPServerConfig(name="test", url="https://example.com/mcp",
                           auth_domain="example.com", scopes=["test.read"])


# --- Stub mode tests (no MCP server URL configured) ---

@pytest.mark.asyncio
async def test_salesforce_stub_mode(sf_config):
    client = SalesforceMCPClient(sf_config)
    assert not client.is_live
    result = await client.call(token="test-token")
    assert result["tool"] == "salesforce_list_contacts"
    assert result["_stub"] is True


@pytest.mark.asyncio
async def test_gcal_stub_mode(gcal_config):
    client = GCalMCPClient(gcal_config)
    assert not client.is_live
    result = await client.call(token="test-token")
    assert result["tool"] == "google_calendar_list_events"
    assert result["_stub"] is True


@pytest.mark.asyncio
async def test_slack_stub_mode(slack_config):
    client = SlackMCPClient(slack_config)
    assert not client.is_live
    result = await client.call(token="test-token")
    assert result["tool"] == "slack_post_message"
    assert result["_stub"] is True


# --- Named method tests ---

@pytest.mark.asyncio
async def test_salesforce_list_contacts(sf_config):
    client = SalesforceMCPClient(sf_config)
    result = await client.list_contacts(token="test-token", query="Acme")
    assert result["tool"] == "salesforce_list_contacts"


@pytest.mark.asyncio
async def test_gcal_list_events(gcal_config):
    client = GCalMCPClient(gcal_config)
    result = await client.list_events(token="test-token", date="2026-03-12")
    assert result["tool"] == "google_calendar_list_events"


@pytest.mark.asyncio
async def test_slack_post_message(slack_config):
    client = SlackMCPClient(slack_config)
    result = await client.post_message(token="test-token",
                                       channel="#general", text="hello")
    assert result["tool"] == "slack_post_message"


# --- Base client tests ---

def test_is_live_false_when_empty_url(sf_config):
    client = BaseMCPClient(sf_config)
    assert not client.is_live


def test_is_live_true_when_url_set(live_config):
    client = BaseMCPClient(live_config)
    assert client.is_live


@pytest.mark.asyncio
async def test_stub_list_tools(sf_config):
    client = BaseMCPClient(sf_config)
    tools = await client.list_tools(token="test-token")
    assert len(tools) == 1
    assert tools[0]["name"] == "stub_tool"
