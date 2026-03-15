"""
OpenClaw Cross-Domain Agent — Version A (AGNTCY Identity Service TBAC).

Orchestrates task execution across Weather and Slack MCP servers on behalf
of a delegating user (Sarah), using:
  - AGNTCY Identity badges for agent identity attestation
  - Okta XAA (RFC 8693) for cross-domain token exchange
  - IdentityServiceMCPMiddleware for TBAC enforcement
"""
import asyncio
import logging
from typing import Any, Dict, List, Optional

from agent.config import AgentConfig
from agent.task_context import TaskContext
from identity.badge_issuer import BadgeIssuer
from identity.badge_verifier import BadgeVerifier
from identity.okta_xaa import OktaXAAClient
from middleware.agntcy_tbac import IdentityServiceMCPMiddleware
from mcp_servers.weather_mcp import WeatherMCPClient
from mcp_servers.slack_mcp import SlackMCPClient

logger = logging.getLogger(__name__)


class OpenClawAgent:
    """
    Main agent orchestrator.

    Lifecycle:
      1. Receive task from delegating user
      2. Obtain AGNTCY identity badge
      3. For each target MCP server:
         a. Exchange token via Okta XAA (RFC 8693)
         b. TBAC middleware validates badge + scopes
         c. Execute MCP tool call
      4. Aggregate results and return to user
    """

    def __init__(self, config: Optional[AgentConfig] = None):
        self.config = config or AgentConfig()
        self.badge_issuer = BadgeIssuer(self.config.identity_service_url)
        self.badge_verifier = BadgeVerifier(self.config.identity_service_url)
        self.xaa_client = OktaXAAClient(
            domain=self.config.okta_domain,
            client_id=self.config.okta_client_id,
            client_secret=self.config.okta_client_secret,
            auth_server_id=self.config.okta_auth_server_id,
        )
        self.middleware = IdentityServiceMCPMiddleware(
            identity_service_url=self.config.identity_service_url,
        )
        self.mcp_clients: Dict[str, Any] = {
            "weather": WeatherMCPClient(self.config.mcp_servers["weather"]),
            "slack": SlackMCPClient(self.config.mcp_servers["slack"]),
        }

    async def execute_task(self, task_description: str) -> Dict[str, Any]:
        """Execute a cross-domain task on behalf of the delegating user."""
        ctx = TaskContext(
            task_description=task_description,
            delegating_user=self.config.delegating_user,
            agent_id=self.config.agent_id,
        )
        logger.info("Starting task %s: %s", ctx.task_id, task_description)

        # Step 1: Obtain AGNTCY identity badge
        badge = await self.badge_issuer.issue_badge(
            agent_id=self.config.agent_id,
            delegating_user=self.config.delegating_user,
            issuer_did=self.config.issuer_did,
        )
        ctx.identity_badge = badge
        logger.info("Badge issued: %s", badge.get("badge_id"))

        # Step 2: Execute across MCP servers
        results: Dict[str, Any] = {}
        for server_name, client in self.mcp_clients.items():
            server_cfg = self.config.mcp_servers[server_name]
            try:
                result = await self._call_mcp_server(
                    ctx=ctx,
                    server_name=server_name,
                    client=client,
                    auth_domain=server_cfg.auth_domain,
                    scopes=server_cfg.scopes,
                )
                results[server_name] = {"status": "success", "data": result}
            except Exception as e:
                logger.error("MCP call to %s failed: %s", server_name, e)
                results[server_name] = {"status": "error", "error": str(e)}

        return {
            "task_id": ctx.task_id,
            "delegation_chain": ctx.get_chain_summary(),
            "results": results,
        }

    async def _call_mcp_server(
        self,
        ctx: TaskContext,
        server_name: str,
        client: Any,
        auth_domain: str,
        scopes: List[str],
    ) -> Any:
        """Call a single MCP server with full identity chain."""
        # Token exchange via Okta XAA
        xaa_token = await self.xaa_client.exchange_token(
            subject_token=ctx.identity_badge.get("jwt", ""),
            target_audience=auth_domain,
            scopes=scopes,
        )
        ctx.add_delegation(
            delegator=self.config.agent_id,
            delegatee=server_name,
            auth_domain=auth_domain,
            scopes=scopes,
            token_ref=xaa_token.get("access_token", "")[:16] + "...",
        )

        # TBAC middleware enforcement
        await self.middleware.enforce(
            badge=ctx.identity_badge,
            target_server=server_name,
            requested_scopes=scopes,
            xaa_token=xaa_token,
        )

        # Execute MCP tool call
        return await client.call(token=xaa_token.get("access_token", ""))


async def main():
    """Demo entry point."""
    agent = OpenClawAgent()
    result = await agent.execute_task(
        "Check the weather in Austin, TX for Sarah's customer meeting "
        "and post a summary to #team-updates on Slack."
    )
    print("Task result:", result)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
