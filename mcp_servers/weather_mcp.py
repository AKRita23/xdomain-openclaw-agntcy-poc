"""
Weather MCP Client.

Connects to Open-Meteo's public weather API to retrieve current conditions
and forecasts on behalf of the delegating user using an XAA-exchanged
access token.

Supports three dispatch modes (see :mod:`mcp_servers.base`):
  * ``stub`` — canned Austin, TX response for offline demos.
  * ``mcp``  — SSE-transported MCP server (not currently offered by
    Open-Meteo; retained for parity).
  * ``rest`` — direct Open-Meteo REST call. The XAA access token is not
    forwarded to Open-Meteo (the public API is unauthenticated), but its
    ``sub`` claim is logged so the XAA → backend handoff is visible in
    demo logs.

Ref: https://open-meteo.com/en/docs
"""
import base64
import json
import logging
from typing import Any, Dict, Optional

import httpx

from mcp_servers.base import BaseMCPClient, MCPToolCallError

logger = logging.getLogger(__name__)

OPEN_METEO_BASE_URL = "https://api.open-meteo.com/v1/forecast"


def _decode_jwt_sub(token: str) -> str:
    """Best-effort extraction of the ``sub`` claim from a JWT for logging.

    No signature verification — upstream layers (badge verifier, TBAC) have
    already authenticated the token by the time a tool call is dispatched.
    Returns ``"<unknown>"`` on any decode failure so logging never breaks a
    tool call.
    """
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return "<unknown>"
        padded = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(padded))
        return str(claims.get("sub", "<unknown>"))
    except Exception:
        return "<unknown>"


class WeatherMCPClient(BaseMCPClient):
    """Client for Open-Meteo weather API via the MCP tool contract."""

    DEFAULT_TOOL = "get_current_weather"

    async def call(self, token: str, tool: Optional[str] = None,
                   arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a tool call on the Weather MCP server.

        Args:
            token: XAA-exchanged access token scoped to api.open-meteo.com
            tool: MCP tool name (e.g., 'get_current_weather')
            arguments: Tool-specific arguments
        """
        tool_name = tool or self.DEFAULT_TOOL
        tool_args = arguments or {}
        return await self._call_tool(
            token=token,
            tool_name=tool_name,
            arguments=tool_args,
        )

    async def get_current_weather(self, token: str,
                                  latitude: float = 30.2672,
                                  longitude: float = -97.7431) -> Dict[str, Any]:
        """Get current weather for given coordinates (default: Austin, TX)."""
        return await self.call(
            token=token,
            tool="get_current_weather",
            arguments={"latitude": latitude, "longitude": longitude},
        )

    async def get_forecast(self, token: str,
                           latitude: float = 30.2672,
                           longitude: float = -97.7431,
                           days: int = 3) -> Dict[str, Any]:
        """Get weather forecast for given coordinates."""
        return await self.call(
            token=token,
            tool="get_forecast",
            arguments={"latitude": latitude, "longitude": longitude, "days": days},
        )

    async def _call_backend(self, token: str, tool_name: str,
                            arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a tool call to the Open-Meteo REST API directly.

        The XAA access token is logged (via its ``sub`` claim) to prove the
        call was authorized by the cross-domain flow, but is not sent to
        Open-Meteo — the public API has no auth.
        """
        sub = _decode_jwt_sub(token)
        logger.info(
            "[Weather MCP] XAA-validated tool call: tool=%s sub=%s args=%s",
            tool_name, sub, arguments,
        )

        latitude = float(arguments.get("latitude", 30.2672))
        longitude = float(arguments.get("longitude", -97.7431))

        if tool_name == "get_current_weather":
            params: Dict[str, Any] = {
                "latitude": latitude,
                "longitude": longitude,
                "current": "temperature_2m,wind_speed_10m,"
                           "relative_humidity_2m,weather_code",
            }
        elif tool_name == "get_forecast":
            days = int(arguments.get("days", 3))
            params = {
                "latitude": latitude,
                "longitude": longitude,
                "daily": "temperature_2m_max,temperature_2m_min,weather_code",
                "forecast_days": days,
            }
        else:
            raise MCPToolCallError(
                f"Unsupported tool for Weather REST backend: {tool_name}"
            )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(OPEN_METEO_BASE_URL, params=params)
                response.raise_for_status()
                data = response.json()
        except httpx.HTTPStatusError as exc:
            raise MCPToolCallError(
                f"Open-Meteo returned HTTP {exc.response.status_code} for "
                f"{tool_name}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise MCPToolCallError(
                f"Open-Meteo request failed for {tool_name}: {exc}"
            ) from exc

        logger.info(
            "[Weather MCP] Open-Meteo responded OK for sub=%s tool=%s",
            sub, tool_name,
        )
        return {"tool": tool_name, "result": data}

    def _stub_call(self, tool_name: str,
                   arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Return mock weather data for stub mode."""
        if tool_name == "get_current_weather":
            return {
                "tool": tool_name,
                "result": {
                    "location": "Austin, TX",
                    "temperature_f": 78.0,
                    "temperature_c": 25.6,
                    "condition": "Partly cloudy",
                    "humidity": 55,
                    "wind_mph": 8.0,
                },
                "_stub": True,
            }
        elif tool_name == "get_forecast":
            days = arguments.get("days", 3)
            return {
                "tool": tool_name,
                "result": {
                    "location": "Austin, TX",
                    "forecast": [
                        {"day": i + 1, "high_f": 82 + i, "low_f": 65 + i,
                         "condition": "Sunny" if i % 2 == 0 else "Partly cloudy"}
                        for i in range(days)
                    ],
                },
                "_stub": True,
            }
        else:
            return {
                "tool": tool_name,
                "result": f"[STUB] {self.config.name}: {tool_name} called with {arguments}",
                "_stub": True,
            }
