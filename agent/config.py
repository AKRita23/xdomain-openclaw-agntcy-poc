"""Agent configuration for cross-domain identity PoC."""
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server connection.

    Dispatch modes (see :class:`mcp_servers.base.BaseMCPClient.mode`):
      * ``stub``  — no ``url`` and ``rest_mode`` is False (default): returns
        placeholder data for offline development.
      * ``mcp``   — ``url`` points at an MCP SSE server; calls use the MCP
        Python SDK transport.
      * ``rest``  — ``rest_mode`` is True; calls are dispatched to the
        subclass's ``_call_backend`` which talks directly to the provider's
        REST API while preserving the MCP tool/arguments contract.
    """
    name: str
    url: str
    auth_domain: str
    scopes: List[str] = field(default_factory=list)
    rest_mode: bool = False
    slack_bot_token: str = ""


@dataclass
class AgentConfig:
    """Top-level agent configuration."""
    agent_id: str = os.getenv("AGENT_ID", "openclaw-agent-001")
    agent_name: str = "OpenClaw Cross-Domain Agent"

    # AGNTCY Identity Service
    identity_service_url: str = os.getenv("AGNTCY_IDENTITY_SERVICE_URL", "http://localhost:8080")
    issuer_did: str = os.getenv("AGNTCY_ISSUER_DID", "")

    # AGNTCY Badge
    agntcy_badge_well_known: str = os.getenv("AGNTCY_BADGE_WELL_KNOWN", "")
    agntcy_badge_id: str = os.getenv("AGNTCY_BADGE_ID", "")
    agntcy_metadata_id: str = os.getenv("AGNTCY_METADATA_ID", "")

    # AWS
    aws_secrets_region: str = os.getenv("AWS_REGION", "us-east-1")

    # Okta XAA (ID-JAG)
    okta_domain: str = os.getenv("OKTA_DOMAIN", "")
    okta_client_id: str = os.getenv("OKTA_CLIENT_ID", "")
    okta_client_secret: str = os.getenv("OKTA_CLIENT_SECRET", "")
    okta_audience: str = os.getenv("OKTA_AUDIENCE", "")
    okta_auth_server_id: str = os.getenv("OKTA_AUTH_SERVER_ID", "default")
    okta_token_endpoint: str = os.getenv("OKTA_TOKEN_ENDPOINT", "")
    okta_issuer: str = os.getenv("OKTA_ISSUER", "")

    # Okta Org 2 (resource domain)
    org2_domain: str = os.getenv("ORG2_DOMAIN", "")
    resource_app_client_id: str = os.getenv("RESOURCE_APP_CLIENT_ID", "")
    resource_app_client_secret: str = os.getenv("RESOURCE_APP_CLIENT_SECRET", "")
    weather_auth_server_id: str = os.getenv("WEATHER_AUTH_SERVER_ID", "ausdd5y4ggr6tY0ou0x7")
    slack_auth_server_id: str = os.getenv("SLACK_AUTH_SERVER_ID", "ausdd60bugz7WGnnE0x7")
    weather_audience: str = os.getenv("WEATHER_AUDIENCE", "https://weather.agentex.io")
    slack_audience: str = os.getenv("SLACK_AUDIENCE", "https://slack.agentex.io")

    # Sarah's pre-obtained token (AWS Secrets Manager)
    sarah_token_secret_id: str = "xdomain-agent-poc/sarah-token"

    # Amazon Verified Permissions
    avp_policy_store_id: str = os.getenv("AVP_POLICY_STORE_ID", "")
    aws_region: str = os.getenv("AWS_REGION", "us-east-1")

    # xaa.dev configuration (used when USE_XAA_DEV=true).
    # Pivot target while the production Okta tenant's XAA audience config is
    # pending vendor support — xaa.dev is Okta's official XAA playground and
    # speaks the same three-step protocol (auth code → ID-JAG → access token).
    # When ``use_xaa_dev`` is False the legacy Okta path above is used.
    use_xaa_dev: bool = os.getenv("USE_XAA_DEV", "false").lower() == "true"
    xaa_idp_url: str = os.getenv("XAA_IDP_URL", "https://idp.xaa.dev")
    xaa_auth_server_url: str = os.getenv(
        "XAA_AUTH_SERVER_URL", "https://auth.resource.xaa.dev"
    )
    xaa_client_id: str = os.getenv("XAA_CLIENT_ID", "")
    xaa_client_secret: str = os.getenv("XAA_CLIENT_SECRET", "")
    xaa_resource_client_id: str = os.getenv("XAA_RESOURCE_CLIENT_ID", "")
    xaa_resource_client_secret: str = os.getenv("XAA_RESOURCE_CLIENT_SECRET", "")
    xaa_redirect_uri: str = os.getenv(
        "XAA_REDIRECT_URI", "http://localhost:8000/callback"
    )
    xaa_resource_audience: str = os.getenv("XAA_RESOURCE_AUDIENCE", "")
    xaa_scope: str = os.getenv("XAA_SCOPE", "openid email")

    # Delegating user
    delegating_user: str = os.getenv("DELEGATING_USER", "sarah@example.com")

    # MCP dispatch modes (step 6 of the XAA flow).
    # When ``*_rest_mode`` is True, the MCP client calls the provider's real
    # REST API directly (Open-Meteo, Slack Web API) while keeping the MCP
    # tool/arguments contract. When False and a URL is configured, it uses
    # the MCP SSE transport. When neither is set, it runs in stub mode.
    weather_mcp_rest_mode: bool = (
        os.getenv("WEATHER_MCP_REST_MODE", "true").lower() == "true"
    )
    slack_mcp_rest_mode: bool = (
        os.getenv("SLACK_MCP_REST_MODE", "true").lower() == "true"
    )
    slack_bot_token: str = os.getenv("SLACK_BOT_TOKEN", "")

    # MCP Server targets
    mcp_servers: Dict[str, MCPServerConfig] = field(default_factory=lambda: {
        "weather": MCPServerConfig(
            name="weather",
            url=os.getenv("WEATHER_MCP_URL", ""),
            auth_domain="api.open-meteo.com",
            scopes=["weather.read"],
            rest_mode=os.getenv("WEATHER_MCP_REST_MODE", "true").lower() == "true",
        ),
        "slack": MCPServerConfig(
            name="slack",
            url=os.getenv("SLACK_MCP_URL", "http://localhost:9003"),
            auth_domain="slack.com",
            scopes=["slack.post.agent-weather-alerts"],
            rest_mode=os.getenv("SLACK_MCP_REST_MODE", "true").lower() == "true",
            slack_bot_token=os.getenv("SLACK_BOT_TOKEN", ""),
        ),
    })
