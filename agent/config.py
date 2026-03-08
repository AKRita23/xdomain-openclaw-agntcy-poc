"""Agent configuration for cross-domain identity PoC."""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server connection."""
    name: str
    url: str
    auth_domain: str
    scopes: List[str] = field(default_factory=list)


@dataclass
class AgentConfig:
    """Top-level agent configuration."""
    agent_id: str = os.getenv("AGENT_ID", "openclaw-agent-001")
    agent_name: str = "OpenClaw Cross-Domain Agent"

    # AGNTCY Identity Service
    identity_service_url: str = os.getenv("AGNTCY_IDENTITY_SERVICE_URL", "http://localhost:8080")
    issuer_did: str = os.getenv("AGNTCY_ISSUER_DID", "")

    # Okta XAA (RFC 8693 Token Exchange)
    okta_domain: str = os.getenv("OKTA_DOMAIN", "")
    okta_client_id: str = os.getenv("OKTA_CLIENT_ID", "")
    okta_client_secret: str = os.getenv("OKTA_CLIENT_SECRET", "")

    # Delegating user
    delegating_user: str = os.getenv("DELEGATING_USER", "sarah@example.com")

    # MCP Server targets
    mcp_servers: Dict[str, MCPServerConfig] = field(default_factory=lambda: {
        "salesforce": MCPServerConfig(
            name="salesforce",
            url=os.getenv("SALESFORCE_MCP_URL", "http://localhost:9001"),
            auth_domain="salesforce.com",
            scopes=["contacts.read", "contacts.write", "opportunities.read"],
        ),
        "gcal": MCPServerConfig(
            name="gcal",
            url=os.getenv("GCAL_MCP_URL", "http://localhost:9002"),
            auth_domain="googleapis.com",
            scopes=["calendar.events.read", "calendar.events.write"],
        ),
        "slack": MCPServerConfig(
            name="slack",
            url=os.getenv("SLACK_MCP_URL", "http://localhost:9003"),
            auth_domain="slack.com",
            scopes=["chat.write", "channels.read"],
        ),
    })
