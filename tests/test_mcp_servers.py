"""Tests for MCP server clients (stub mode -- no live MCP servers needed)."""
import pytest
from agent.config import MCPServerConfig
from mcp_servers.base import BaseMCPClient
from mcp_servers.weather_mcp import WeatherMCPClient
from mcp_servers.slack_mcp import SlackMCPClient


@pytest.fixture
def weather_config():
    return MCPServerConfig(name="weather", url="",
                           auth_domain="api.open-meteo.com", scopes=["weather:read"])


@pytest.fixture
def slack_config():
    return MCPServerConfig(name="slack", url="",
                           auth_domain="slack.com", scopes=["slack:chat:write"])


@pytest.fixture
def live_config():
    """Config with a URL set -- simulates live mode (won't actually connect)."""
    return MCPServerConfig(name="test", url="https://example.com/mcp",
                           auth_domain="example.com", scopes=["test.read"])


# --- Stub mode tests (no MCP server URL configured) ---

@pytest.mark.asyncio
async def test_weather_stub_mode(weather_config):
    client = WeatherMCPClient(weather_config)
    assert not client.is_live
    result = await client.call(token="test-token")
    assert result["tool"] == "get_current_weather"
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
async def test_weather_get_current(weather_config):
    client = WeatherMCPClient(weather_config)
    result = await client.get_current_weather(token="test-token",
                                               latitude=30.2672, longitude=-97.7431)
    assert result["tool"] == "get_current_weather"
    assert result["result"]["location"] == "Austin, TX"


@pytest.mark.asyncio
async def test_weather_get_forecast(weather_config):
    client = WeatherMCPClient(weather_config)
    result = await client.get_forecast(token="test-token",
                                        latitude=30.2672, longitude=-97.7431, days=3)
    assert result["tool"] == "get_forecast"
    assert len(result["result"]["forecast"]) == 3


@pytest.mark.asyncio
async def test_slack_post_message(slack_config):
    client = SlackMCPClient(slack_config)
    result = await client.post_message(token="test-token",
                                       channel="#general", text="hello")
    assert result["tool"] == "slack_post_message"


# --- Base client tests ---

def test_is_live_false_when_empty_url(weather_config):
    client = BaseMCPClient(weather_config)
    assert not client.is_live


def test_is_live_true_when_url_set(live_config):
    client = BaseMCPClient(live_config)
    assert client.is_live


@pytest.mark.asyncio
async def test_stub_list_tools(weather_config):
    client = BaseMCPClient(weather_config)
    tools = await client.list_tools(token="test-token")
    assert len(tools) == 1
    assert tools[0]["name"] == "stub_tool"
