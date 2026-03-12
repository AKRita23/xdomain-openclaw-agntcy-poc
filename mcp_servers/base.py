"""
Base MCP Client.

Provides the shared MCP protocol client logic for connecting to
official first-party MCP servers (Salesforce, Google, Slack) via
the MCP Python SDK.

Supports SSE (HTTP+Server-Sent Events) transport for remote servers.
"""
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MCPConnectionError(Exception):
    """Raised when MCP server connection fails."""
    pass


class MCPToolCallError(Exception):
    """Raised when an MCP tool call returns an error."""
    pass


class BaseMCPClient:
    """
    Base class for MCP server clients.

    Connects to an official MCP server using the MCP Python SDK's
    SSE client transport. Each subclass targets a specific provider's
    MCP server (Salesforce, Google Calendar, Slack).

    In local dev / test mode (when url is empty), returns placeholder
    responses so the agent can run end-to-end without live MCP servers.
    """

    def __init__(self, config: Any):
        self.config = config
        self._session = None

    @property
    def is_live(self) -> bool:
        """True if a real MCP server URL is configured."""
        return bool(self.config.url)

    async def connect(self, token: str) -> None:
        """
        Establish connection to the MCP server.

        Uses the MCP Python SDK's SSE client transport with the
        XAA-exchanged bearer token for authentication.
        """
        if not self.is_live:
            logger.info(
                "[%s] No URL configured, running in stub mode",
                self.config.name,
            )
            return

        try:
            from mcp import ClientSession
            from mcp.client.sse import sse_client

            headers = {"Authorization": f"Bearer {token}"}
            read_stream, write_stream = await sse_client(
                url=self.config.url,
                headers=headers,
            ).__aenter__()
            self._session = ClientSession(read_stream, write_stream)
            await self._session.__aenter__()
            await self._session.initialize()
            logger.info("[%s] Connected to MCP server at %s",
                        self.config.name, self.config.url)
        except ImportError:
            logger.warning(
                "[%s] MCP SDK not installed, running in stub mode. "
                "Install with: pip install mcp",
                self.config.name,
            )
        except Exception as e:
            raise MCPConnectionError(
                f"Failed to connect to {self.config.name} MCP server "
                f"at {self.config.url}: {e}"
            ) from e

    async def list_tools(self, token: str) -> List[Dict[str, Any]]:
        """List available tools on the MCP server."""
        if not self.is_live:
            return self._stub_list_tools()

        await self.connect(token)
        if not self._session:
            return self._stub_list_tools()

        result = await self._session.list_tools()
        return [
            {"name": t.name, "description": t.description}
            for t in result.tools
        ]

    async def _call_tool(self, token: str, tool_name: str,
                         arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Call a tool on the MCP server.

        If no live server is configured, returns a stub response.
        """
        if not self.is_live:
            logger.info(
                "[%s] Stub mode: tool=%s args=%s",
                self.config.name, tool_name, arguments,
            )
            return self._stub_call(tool_name, arguments)

        await self.connect(token)
        if not self._session:
            return self._stub_call(tool_name, arguments)

        result = await self._session.call_tool(tool_name, arguments)
        if result.isError:
            raise MCPToolCallError(
                f"Tool {tool_name} on {self.config.name} returned error: "
                f"{result.content}"
            )
        # Extract text content from MCP result
        content = []
        for block in result.content:
            if hasattr(block, "text"):
                content.append(block.text)
        return {
            "tool": tool_name,
            "result": content[0] if len(content) == 1 else content,
        }

    async def disconnect(self) -> None:
        """Close the MCP session."""
        if self._session:
            await self._session.__aexit__(None, None, None)
            self._session = None

    def _stub_list_tools(self) -> List[Dict[str, Any]]:
        """Return placeholder tool list for stub mode."""
        return [{"name": "stub_tool", "description": "Stub — no MCP server configured"}]

    def _stub_call(self, tool_name: str,
                   arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Return placeholder response for stub mode."""
        return {
            "tool": tool_name,
            "result": f"[STUB] {self.config.name}: {tool_name} called with {arguments}",
            "_stub": True,
        }
