"""
Weather MCP Client.

Connects to Open-Meteo's public weather API to retrieve current conditions
and forecasts on behalf of the delegating user using an XAA-exchanged
access token.

Ref: https://open-meteo.com/en/docs
"""
import json
import logging
import urllib.request
from typing import Any, Dict, Optional

from mcp_servers.base import BaseMCPClient

logger = logging.getLogger(__name__)

OPEN_METEO_BASE_URL = "https://api.open-meteo.com/v1/forecast"


class WeatherMCPClient(BaseMCPClient):
    """Client for Open-Meteo weather API via MCP."""

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
