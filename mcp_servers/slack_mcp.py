"""
Slack MCP Client.

Exposes the MCP tool contract for Slack operations (post message, search,
list channels). Dispatch can run in three modes (see
:mod:`mcp_servers.base`):

  * ``stub`` — canned response for offline demos.
  * ``mcp``  — Slack's hosted MCP server (closed-partner — not available
    for demo use today; retained for parity).
  * ``rest`` — direct Slack Web API call. The architectural story is:
    the XAA access token authorizes the agent to make the call; the
    actual Slack API request uses a configured bot token (kept separate
    from the XAA token for logical separation).

Ref: https://docs.slack.dev/ai/slack-mcp-server/ and
https://api.slack.com/web
"""
import logging
from typing import Any, Dict, Optional

import httpx

from mcp_servers.base import BaseMCPClient, MCPToolCallError
from mcp_servers.weather_mcp import _decode_jwt_sub

logger = logging.getLogger(__name__)

SLACK_API_BASE = "https://slack.com/api"


def _truncate_token(token: str, keep: int = 10) -> str:
    """Return a log-safe token prefix. Never log the full Slack bot token."""
    if not token:
        return "<empty>"
    return f"{token[:keep]}...(truncated, len={len(token)})"


class SlackMCPClient(BaseMCPClient):
    """Client for Slack via the MCP tool contract."""

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

    async def _call_backend(self, token: str, tool_name: str,
                            arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatch a tool call to the Slack Web API directly.

        The ``token`` parameter (XAA access token) is NOT sent to Slack —
        Slack's API requires a bot token, which is pulled from
        ``config.slack_bot_token``. The XAA token's ``sub`` claim is logged
        to make the cross-domain authorization narrative visible in demo
        logs.
        """
        slack_bot_token = getattr(self.config, "slack_bot_token", "") or ""
        if not slack_bot_token:
            raise MCPToolCallError(
                "Slack rest mode requires config.slack_bot_token "
                "(SLACK_BOT_TOKEN env var) to be set"
            )

        sub = _decode_jwt_sub(token)
        logger.info(
            "[Slack MCP] XAA-validated tool call from sub=%s; using "
            "configured Slack bot token (%s) to invoke real Slack API "
            "tool=%s args=%s",
            sub,
            _truncate_token(slack_bot_token),
            tool_name,
            arguments,
        )

        headers = {"Authorization": f"Bearer {slack_bot_token}"}

        if tool_name == "slack_post_message":
            url = f"{SLACK_API_BASE}/chat.postMessage"
            body = {
                "channel": arguments.get("channel", ""),
                "text": arguments.get("text", ""),
            }
            response_data = await self._post_json(url, headers, body)
        elif tool_name == "slack_search_messages":
            url = f"{SLACK_API_BASE}/search.messages"
            body = {"query": arguments.get("query", "")}
            response_data = await self._post_json(url, headers, body)
        elif tool_name == "slack_list_channels":
            url = f"{SLACK_API_BASE}/conversations.list"
            response_data = await self._get(url, headers, arguments)
        else:
            raise MCPToolCallError(
                f"Unsupported tool for Slack REST backend: {tool_name}"
            )

        if not response_data.get("ok", False):
            slack_error = response_data.get("error", "unknown_error")
            raise MCPToolCallError(
                f"Slack API returned error for {tool_name}: {slack_error}"
            )

        logger.info(
            "[Slack MCP] Slack API responded ok for sub=%s tool=%s",
            sub, tool_name,
        )
        return {"tool": tool_name, "result": response_data}

    async def _post_json(self, url: str, headers: Dict[str, str],
                         body: Dict[str, Any]) -> Dict[str, Any]:
        """POST JSON to Slack and return parsed response.

        Slack always responds with 200 + ``{ok: bool, ...}`` even for
        logical errors, so status-based failures are genuinely exceptional.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(url, headers=headers, json=body)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            raise MCPToolCallError(
                f"Slack API returned HTTP {exc.response.status_code} at "
                f"{url}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise MCPToolCallError(
                f"Slack API request failed at {url}: {exc}"
            ) from exc

    async def _get(self, url: str, headers: Dict[str, str],
                   params: Dict[str, Any]) -> Dict[str, Any]:
        """GET from Slack with query params and return parsed response."""
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(url, headers=headers, params=params)
                response.raise_for_status()
                return response.json()
        except httpx.HTTPStatusError as exc:
            raise MCPToolCallError(
                f"Slack API returned HTTP {exc.response.status_code} at "
                f"{url}: {exc.response.text[:200]}"
            ) from exc
        except httpx.HTTPError as exc:
            raise MCPToolCallError(
                f"Slack API request failed at {url}: {exc}"
            ) from exc
