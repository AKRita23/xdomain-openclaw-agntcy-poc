"""Agent configuration for cross-domain identity PoC."""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MCPServerConfig:
    """Configuration for connecting to an official MCP server."""
    name: str
    url: str
    auth_domain: str
    transport: str = "sse"  # "sse" (HTTP+SSE) or "stdio"
    scopes: List[str] = field(default_factory=list)


@dataclass
class AgentConfig:
    """Top-level agent configuration."""
    agent_id: str = os.getenv("AGENT_ID", "openclaw-agent-001")
    agent_name: str = "OpenClaw Cross-Domain Agent"

    # AGNTCY Identity Service
    identity_service_url: str = os.getenv("AGNTCY_IDENTITY_SERVICE_URL", "http://localhost:8080")
    issuer_did: str = os.getenv("AGNTCY_ISSUER_DID", "")

    # Auth0 (agent identity — client_credentials)
    auth0_domain: str = os.getenv("AUTH0_DOMAIN", "")
    auth0_client_id: str = os.getenv("AUTH0_CLIENT_ID", "")
    auth0_client_secret: str = os.getenv("AUTH0_CLIENT_SECRET", "")
    auth0_secret_arn: Optional[str] = os.getenv("AUTH0_SECRET_ARN")

    # Okta (RFC 8693 token exchange)
    okta_domain: str = os.getenv("OKTA_DOMAIN", "")
    okta_auth_server_id: str = os.getenv("OKTA_AUTH_SERVER_ID", "default")

    # Delegating user
    delegating_user: str = os.getenv("DELEGATING_USER", "sarah@example.com")

    # Official MCP Server connections
    mcp_servers: Dict[str, MCPServerConfig] = field(default_factory=lambda: {
        "salesforce": MCPServerConfig(
            name="salesforce",
            url=os.getenv("SALESFORCE_MCP_URL", ""),
            auth_domain="salesforce.com",
            transport="sse",
            scopes=["contacts.read", "contacts.write", "opportunities.read"],
        ),
        "gcal": MCPServerConfig(
            name="gcal",
            url=os.getenv("GCAL_MCP_URL", ""),
            auth_domain="googleapis.com",
            transport="sse",
            scopes=["calendar.events.read", "calendar.events.write"],
        ),
        "slack": MCPServerConfig(
            name="slack",
            url=os.getenv("SLACK_MCP_URL", ""),
            auth_domain="slack.com",
            transport="sse",
            scopes=["chat.write", "channels.read"],
        ),
    })
