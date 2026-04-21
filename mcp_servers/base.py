"""
Base MCP Client.

Provides the shared dispatch logic for MCP tool calls. Each concrete client
(Weather, Slack) subclasses :class:`BaseMCPClient` and decides how a tool
call reaches the real backend by selecting one of three dispatch modes:

* ``stub`` — no ``url`` and ``rest_mode`` is False. Returns placeholder
  data from :meth:`_stub_call` so the agent can run fully offline.
* ``mcp``  — ``config.url`` is set. Uses the MCP Python SDK SSE transport
  to talk to an MCP-protocol server.
* ``rest`` — ``config.rest_mode`` is True. Routes to the subclass's
  :meth:`_call_backend`, which calls the provider's REST API directly while
  preserving the MCP tool-name + arguments + bearer-token contract.

``rest`` takes precedence over ``mcp`` when both are configured, matching
the XAA PoC's demo posture where Slack MCP (closed-partner) and Open-Meteo
(no MCP endpoint) are reached via their native REST APIs.
"""
import logging
from typing import Any, Dict, List

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

    Provides dispatch across three modes — stub, MCP-protocol SSE, and
    direct REST — based on the ``config`` passed in. Subclasses implement
    :meth:`_stub_call` (for stub mode) and :meth:`_call_backend` (for rest
    mode); the MCP-protocol path is handled here.
    """

    def __init__(self, config: Any):
        self.config = config
        self._session = None

    @property
    def is_live(self) -> bool:
        """True if either a real MCP server URL or rest mode is configured."""
        return bool(self.config.url) or self._rest_mode_enabled

    @property
    def _rest_mode_enabled(self) -> bool:
        """Whether the config opts into direct REST backend calls."""
        return bool(getattr(self.config, "rest_mode", False))

    @property
    def mode(self) -> str:
        """Return the active dispatch mode: ``rest``, ``mcp``, or ``stub``.

        Precedence is rest > mcp > stub so a config can pin ``rest_mode=True``
        even when a stale ``url`` remains set. This matches demo usage where
        the orchestrator flips to REST while keeping the legacy URL around.
        """
        if self._rest_mode_enabled:
            return "rest"
        if self.config.url:
            return "mcp"
        return "stub"

    async def connect(self, token: str) -> None:
        """
        Establish connection to the MCP server (MCP mode only).

        No-op in stub and rest modes — those dispatch paths don't use the
        persistent SSE session.
        """
        if self.mode != "mcp":
            logger.info(
                "[%s] No MCP session needed (mode=%s)",
                self.config.name, self.mode,
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
        if self.mode != "mcp":
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
        Dispatch a tool call based on :attr:`mode`.

        * ``stub`` → :meth:`_stub_call` (offline placeholder)
        * ``mcp``  → SSE session → ``call_tool``
        * ``rest`` → :meth:`_call_backend` (subclass talks to real REST API)
        """
        dispatch_mode = self.mode
        if dispatch_mode == "stub":
            logger.info(
                "[%s] dispatch=stub tool=%s args=%s",
                self.config.name, tool_name, arguments,
            )
            return self._stub_call(tool_name, arguments)

        if dispatch_mode == "rest":
            logger.info(
                "[%s] dispatch=rest tool=%s args=%s",
                self.config.name, tool_name, arguments,
            )
            return await self._call_backend(token, tool_name, arguments)

        # mcp
        logger.info(
            "[%s] dispatch=mcp url=%s tool=%s args=%s",
            self.config.name, self.config.url, tool_name, arguments,
        )
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

    async def _call_backend(self, token: str, tool_name: str,
                            arguments: Dict[str, Any]) -> Dict[str, Any]:
        """REST-mode dispatch hook. Subclasses MUST override.

        Implementations should call the provider's real REST API with
        ``arguments`` and return a dict shaped like the stub response so
        callers can treat both modes uniformly.
        """
        raise NotImplementedError(
            "Subclass must implement _call_backend for rest mode"
        )

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
