"""Tests for the ``rest`` dispatch mode on MCP clients.

Exercises:
  * :attr:`BaseMCPClient.mode` correctly resolves ``rest`` / ``mcp`` / ``stub``
    based on ``url`` + ``rest_mode``.
  * :meth:`BaseMCPClient._call_tool` routes to ``_call_backend`` in rest mode.
  * :class:`WeatherMCPClient._call_backend` hits Open-Meteo with the right
    params and maps errors to :class:`MCPToolCallError`.
  * :class:`SlackMCPClient._call_backend` uses the SLACK BOT token (not the
    XAA token) for auth, and maps ``ok: false`` to :class:`MCPToolCallError`.
"""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional

import httpx
import pytest

from agent.config import MCPServerConfig
from mcp_servers.base import BaseMCPClient, MCPToolCallError
from mcp_servers.slack_mcp import SlackMCPClient
from mcp_servers.weather_mcp import WeatherMCPClient


# --------------------------------------------------------------------------- helpers


def _build_jwt(claims: Dict[str, Any]) -> str:
    """Build an unsigned JWT-shaped string with the given claims.

    Only the payload segment matters — upstream layers do the signature
    verification, and the dispatch layer just reads ``sub`` for logging.
    """
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    header = _b64(json.dumps({"alg": "none", "typ": "JWT"}).encode())
    payload = _b64(json.dumps(claims).encode())
    return f"{header}.{payload}.sig"


class _FakeResponse:
    """Minimal httpx.Response stand-in for the code paths we exercise."""

    def __init__(self, status_code: int = 200,
                 json_data: Optional[Dict[str, Any]] = None,
                 text: str = "") -> None:
        self.status_code = status_code
        self._json = json_data if json_data is not None else {}
        self.text = text or json.dumps(self._json)

    def json(self) -> Dict[str, Any]:
        return self._json

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "http://fake.test")
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=request,
                response=self,  # type: ignore[arg-type]
            )


class _FakeHTTPX:
    """Handle to read recorded calls and script the next response."""

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.response: _FakeResponse = _FakeResponse(json_data={"ok": True})

    def set_response(self, response: _FakeResponse) -> None:
        self.response = response


@pytest.fixture
def fake_httpx(monkeypatch) -> _FakeHTTPX:
    """Replace ``httpx.AsyncClient`` inside the weather + slack modules."""
    handle = _FakeHTTPX()

    class _FakeAsyncClient:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        async def __aenter__(self) -> "_FakeAsyncClient":
            return self

        async def __aexit__(self, *_args) -> None:
            return None

        async def get(self, url, params=None, headers=None):
            handle.calls.append({
                "method": "GET", "url": url,
                "params": dict(params) if params else {},
                "headers": dict(headers) if headers else {},
            })
            return handle.response

        async def post(self, url, headers=None, json=None):
            handle.calls.append({
                "method": "POST", "url": url,
                "headers": dict(headers) if headers else {},
                "json": dict(json) if json else {},
            })
            return handle.response

    import mcp_servers.slack_mcp as slack_mod
    import mcp_servers.weather_mcp as weather_mod
    monkeypatch.setattr(weather_mod.httpx, "AsyncClient", _FakeAsyncClient)
    monkeypatch.setattr(slack_mod.httpx, "AsyncClient", _FakeAsyncClient)
    return handle


# --------------------------------------------------------------------------- base mode


def test_mode_rest_when_rest_mode_true():
    cfg = MCPServerConfig(
        name="weather", url="", auth_domain="api.open-meteo.com",
        scopes=["weather:read"], rest_mode=True,
    )
    assert BaseMCPClient(cfg).mode == "rest"


def test_mode_rest_wins_over_mcp_when_both_set():
    cfg = MCPServerConfig(
        name="slack", url="http://example.com/mcp",
        auth_domain="slack.com", scopes=["slack:chat:write"],
        rest_mode=True,
    )
    assert BaseMCPClient(cfg).mode == "rest"


def test_mode_mcp_when_only_url_set():
    cfg = MCPServerConfig(
        name="slack", url="http://example.com/mcp",
        auth_domain="slack.com", scopes=["slack:chat:write"],
    )
    assert BaseMCPClient(cfg).mode == "mcp"


def test_mode_stub_when_nothing_configured():
    cfg = MCPServerConfig(
        name="weather", url="", auth_domain="api.open-meteo.com",
        scopes=["weather:read"],
    )
    assert BaseMCPClient(cfg).mode == "stub"


@pytest.mark.asyncio
async def test_base_call_tool_dispatches_to_call_backend_in_rest_mode():
    """In rest mode, :meth:`_call_tool` must route to ``_call_backend``."""
    captured: Dict[str, Any] = {}

    class _RecordingClient(BaseMCPClient):
        async def _call_backend(self, token, tool_name, arguments):
            captured["token"] = token
            captured["tool_name"] = tool_name
            captured["arguments"] = arguments
            return {"tool": tool_name, "result": "from-backend"}

    cfg = MCPServerConfig(
        name="demo", url="", auth_domain="demo.test",
        scopes=[], rest_mode=True,
    )
    client = _RecordingClient(cfg)
    out = await client._call_tool(
        token="xaa.token",
        tool_name="demo_tool",
        arguments={"k": "v"},
    )
    assert out == {"tool": "demo_tool", "result": "from-backend"}
    assert captured == {
        "token": "xaa.token",
        "tool_name": "demo_tool",
        "arguments": {"k": "v"},
    }


@pytest.mark.asyncio
async def test_base_call_backend_raises_not_implemented_by_default():
    cfg = MCPServerConfig(
        name="demo", url="", auth_domain="demo.test",
        scopes=[], rest_mode=True,
    )
    client = BaseMCPClient(cfg)
    with pytest.raises(NotImplementedError):
        await client._call_tool(
            token="xaa.token",
            tool_name="demo_tool",
            arguments={},
        )


# --------------------------------------------------------------------------- weather rest


@pytest.fixture
def weather_rest_config():
    return MCPServerConfig(
        name="weather", url="",
        auth_domain="api.open-meteo.com", scopes=["weather:read"],
        rest_mode=True,
    )


@pytest.mark.asyncio
async def test_weather_rest_get_current_weather(fake_httpx, weather_rest_config):
    fake_httpx.set_response(_FakeResponse(json_data={
        "latitude": 30.25, "longitude": -97.75,
        "current": {
            "temperature_2m": 25.6,
            "wind_speed_10m": 8.0,
            "relative_humidity_2m": 55,
            "weather_code": 2,
        },
    }))

    client = WeatherMCPClient(weather_rest_config)
    token = _build_jwt({"sub": "akritaws@gmail.com"})
    result = await client.get_current_weather(
        token=token, latitude=30.2672, longitude=-97.7431,
    )

    assert len(fake_httpx.calls) == 1
    call = fake_httpx.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://api.open-meteo.com/v1/forecast"
    assert call["params"]["latitude"] == 30.2672
    assert call["params"]["longitude"] == -97.7431
    assert call["params"]["current"] == (
        "temperature_2m,wind_speed_10m,relative_humidity_2m,weather_code"
    )
    # XAA token is NOT forwarded to Open-Meteo (public API)
    assert "Authorization" not in call["headers"]

    assert result["tool"] == "get_current_weather"
    assert result["result"]["current"]["temperature_2m"] == 25.6


@pytest.mark.asyncio
async def test_weather_rest_get_forecast_passes_days(fake_httpx, weather_rest_config):
    fake_httpx.set_response(_FakeResponse(json_data={
        "daily": {
            "temperature_2m_max": [82, 83, 84, 85, 86],
            "temperature_2m_min": [65, 66, 67, 68, 69],
            "weather_code": [0, 1, 2, 3, 4],
        },
    }))

    client = WeatherMCPClient(weather_rest_config)
    token = _build_jwt({"sub": "sarah@example.com"})
    await client.get_forecast(token=token, days=5)

    call = fake_httpx.calls[0]
    assert call["params"]["forecast_days"] == 5
    assert call["params"]["daily"] == (
        "temperature_2m_max,temperature_2m_min,weather_code"
    )


@pytest.mark.asyncio
async def test_weather_rest_http_error_becomes_mcp_tool_call_error(
    fake_httpx, weather_rest_config,
):
    fake_httpx.set_response(_FakeResponse(
        status_code=503, text="Service Unavailable",
    ))
    client = WeatherMCPClient(weather_rest_config)
    token = _build_jwt({"sub": "sarah@example.com"})
    with pytest.raises(MCPToolCallError) as excinfo:
        await client.get_current_weather(token=token)
    assert "503" in str(excinfo.value)


@pytest.mark.asyncio
async def test_weather_rest_unknown_tool_raises(fake_httpx, weather_rest_config):
    client = WeatherMCPClient(weather_rest_config)
    token = _build_jwt({"sub": "sarah@example.com"})
    with pytest.raises(MCPToolCallError):
        await client.call(token=token, tool="weather_explode", arguments={})
    assert fake_httpx.calls == []  # short-circuits before any HTTP call


# --------------------------------------------------------------------------- slack rest


@pytest.fixture
def slack_rest_config():
    return MCPServerConfig(
        name="slack", url="", auth_domain="slack.com",
        scopes=["slack:chat:write", "slack:channels:read"],
        rest_mode=True,
        slack_bot_token="xoxb-1234567890-abcdefg",
    )


@pytest.mark.asyncio
async def test_slack_rest_post_message_uses_slack_bot_token_not_xaa_token(
    fake_httpx, slack_rest_config,
):
    fake_httpx.set_response(_FakeResponse(json_data={
        "ok": True, "channel": "C123", "ts": "1234567890.000100",
    }))

    client = SlackMCPClient(slack_rest_config)
    xaa_token = _build_jwt({"sub": "akritaws@gmail.com"})
    result = await client.post_message(
        token=xaa_token, channel="#general", text="hello from XAA",
    )

    assert len(fake_httpx.calls) == 1
    call = fake_httpx.calls[0]
    assert call["method"] == "POST"
    assert call["url"] == "https://slack.com/api/chat.postMessage"
    # Critical: Slack auth uses the bot token, not the XAA access token.
    auth = call["headers"]["Authorization"]
    assert auth == "Bearer xoxb-1234567890-abcdefg"
    assert xaa_token not in auth
    assert call["json"] == {"channel": "#general", "text": "hello from XAA"}

    assert result["tool"] == "slack_post_message"
    assert result["result"]["ok"] is True


@pytest.mark.asyncio
async def test_slack_rest_raises_on_ok_false(fake_httpx, slack_rest_config):
    fake_httpx.set_response(_FakeResponse(json_data={
        "ok": False, "error": "channel_not_found",
    }))
    client = SlackMCPClient(slack_rest_config)
    token = _build_jwt({"sub": "sarah@example.com"})
    with pytest.raises(MCPToolCallError) as excinfo:
        await client.post_message(token=token, channel="#nope", text="x")
    assert "channel_not_found" in str(excinfo.value)


@pytest.mark.asyncio
async def test_slack_rest_requires_slack_bot_token(fake_httpx):
    cfg = MCPServerConfig(
        name="slack", url="", auth_domain="slack.com",
        scopes=["slack:chat:write"], rest_mode=True,
        slack_bot_token="",  # missing
    )
    client = SlackMCPClient(cfg)
    token = _build_jwt({"sub": "sarah@example.com"})
    with pytest.raises(MCPToolCallError) as excinfo:
        await client.post_message(token=token, channel="#g", text="x")
    assert "slack_bot_token" in str(excinfo.value)


@pytest.mark.asyncio
async def test_slack_rest_list_channels_uses_get(fake_httpx, slack_rest_config):
    fake_httpx.set_response(_FakeResponse(json_data={
        "ok": True, "channels": [{"id": "C1", "name": "general"}],
    }))
    client = SlackMCPClient(slack_rest_config)
    token = _build_jwt({"sub": "sarah@example.com"})
    result = await client.list_channels(token=token)

    call = fake_httpx.calls[0]
    assert call["method"] == "GET"
    assert call["url"] == "https://slack.com/api/conversations.list"
    assert call["headers"]["Authorization"] == "Bearer xoxb-1234567890-abcdefg"
    assert result["result"]["channels"][0]["name"] == "general"
