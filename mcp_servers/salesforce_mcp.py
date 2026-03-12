"""
Salesforce MCP Client.

Connects to Salesforce's official hosted MCP server to execute
tool calls (contacts, opportunities, etc.) on behalf of the
delegating user using an XAA-exchanged access token.

Ref: https://help.salesforce.com/s/articleView?id=platform.hosted_mcp_servers.htm
"""
import logging
from typing import Any, Dict, List, Optional

from mcp_servers.base import BaseMCPClient

logger = logging.getLogger(__name__)


class SalesforceMCPClient(BaseMCPClient):
    """Client for Salesforce's official MCP server."""

    # Default tools to call when executing a cross-domain task
    DEFAULT_TOOL = "salesforce_list_contacts"

    async def call(self, token: str, tool: Optional[str] = None,
                   arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute a tool call on the Salesforce MCP server.

        Args:
            token: XAA-exchanged access token scoped to salesforce.com
            tool: MCP tool name (e.g., 'salesforce_list_contacts')
            arguments: Tool-specific arguments
        """
        tool_name = tool or self.DEFAULT_TOOL
        tool_args = arguments or {}
        return await self._call_tool(
            token=token,
            tool_name=tool_name,
            arguments=tool_args,
        )

    async def list_contacts(self, token: str,
                            query: Optional[str] = None) -> Dict[str, Any]:
        """List Salesforce contacts, optionally filtered by query."""
        args = {}
        if query:
            args["query"] = query
        return await self.call(token=token, tool="salesforce_list_contacts",
                               arguments=args)

    async def get_opportunities(self, token: str) -> Dict[str, Any]:
        """List Salesforce opportunities."""
        return await self.call(token=token, tool="salesforce_list_opportunities")
