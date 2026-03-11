"""
Slack MCP Client.

Connects to Slack's official MCP server to execute tool calls
(post messages, search, read channels) on behalf of the delegating user
using an XAA-exchanged access token.

Ref: https://docs.slack.dev/ai/slack-mcp-server/
"""
import logging
from typing import Any, Dict, Optional

from mcp_servers.base import BaseMCPClient

logger = logging.getLogger(__name__)


class SlackMCPClient(BaseMCPClient):
    """Client for Slack's official MCP server."""

    DEFAULT_TOOL = "slack_post_message"

    async def call(self, token: str, tool: Optional[str] = None,
                   arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a tool call on the Slack MCP server.

        Args:
            token: XAA-exchanged access token scoped to slack.com
            tool: MCP tool name (e.g., 'slack_post_message')
            arguments: Tool-specific arguments
        """
        tool_name = tool or self.DEFAULT_TOOL
        tool_args = arguments or {}
        return await self._call_tool(
            token=token,
            tool_name=tool_name,
            arguments=tool_args,
        )

    async def post_message(self, token: str, channel: str,
                           text: str) -> Dict[str, Any]:
        """Post a message to a Slack channel."""
        return await self.call(
            token=token,
            tool="slack_post_message",
            arguments={"channel": channel, "text": text},
        )

    async def search_messages(self, token: str,
                              query: str) -> Dict[str, Any]:
        """Search Slack messages."""
        return await self.call(
            token=token,
            tool="slack_search_messages",
            arguments={"query": query},
        )

    async def list_channels(self, token: str) -> Dict[str, Any]:
        """List accessible Slack channels."""
        return await self.call(token=token, tool="slack_list_channels")
