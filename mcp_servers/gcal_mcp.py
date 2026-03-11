"""
Google Calendar MCP Client.

Connects to Google's official MCP server to execute tool calls
(list events, create events, etc.) on behalf of the delegating user
using an XAA-exchanged access token.

Ref: https://cloud.google.com/blog/products/ai-machine-learning/announcing-official-mcp-support-for-google-services
"""
import logging
from typing import Any, Dict, Optional

from mcp_servers.base import BaseMCPClient

logger = logging.getLogger(__name__)


class GCalMCPClient(BaseMCPClient):
    """Client for Google's official Calendar MCP server."""

    DEFAULT_TOOL = "google_calendar_list_events"

    async def call(self, token: str, tool: Optional[str] = None,
                   arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a tool call on the Google Calendar MCP server.

        Args:
            token: XAA-exchanged access token scoped to googleapis.com
            tool: MCP tool name (e.g., 'google_calendar_list_events')
            arguments: Tool-specific arguments
        """
        tool_name = tool or self.DEFAULT_TOOL
        tool_args = arguments or {}
        return await self._call_tool(
            token=token,
            tool_name=tool_name,
            arguments=tool_args,
        )

    async def list_events(self, token: str,
                          date: Optional[str] = None) -> Dict[str, Any]:
        """List calendar events, optionally for a specific date."""
        args = {}
        if date:
            args["date"] = date
        return await self.call(token=token, tool="google_calendar_list_events",
                               arguments=args)

    async def create_event(self, token: str, title: str,
                           start: str, end: str) -> Dict[str, Any]:
        """Create a new calendar event."""
        return await self.call(
            token=token,
            tool="google_calendar_create_event",
            arguments={"title": title, "start": start, "end": end},
        )
