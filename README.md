# Cross-Domain Agent Identity PoC — Version A: AGNTCY Identity Service TBAC

> OpenClaw agent executing cross-domain tasks on behalf of a human user (Sarah),
> with identity attestation via AGNTCY Identity badges and Task-Based Access
> Control (TBAC) enforcement via IdentityServiceMCPMiddleware.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Human User (Sarah)                          │
│                     delegates task to agent                        │
└────────────────────────────┬────────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      OpenClaw Agent                                 │
│                                                                     │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────────┐ │
│  │ AGNTCY Badge │  │  Okta XAA        │  │ TBAC Middleware       │ │
│  │ (Identity)   │  │  (RFC 8693)      │  │ (IdentityService     │ │
│  │              │  │                  │  │  MCPMiddleware)       │ │
│  └──────┬───────┘  └────────┬─────────┘  └──────────┬────────────┘ │
└─────────┼───────────────────┼───────────────────────┼──────────────┘
          │                   │                       │
          ▼                   ▼                       ▼
┌──────────────┐                             ┌──────────────┐
│   Weather    │                             │    Slack     │
│  (Open-Meteo)│                             │  MCP Server  │
│              │                             │              │
│ Domain:      │                             │ Domain:      │
│ api.open-    │                             │ slack.com    │
│ meteo.com    │                             │              │
└──────────────┘                             └──────────────┘
```

## Layers

### 1. AGNTCY Identity Badge
- The agent obtains a verifiable identity badge from the AGNTCY Identity Service
- Badge contains: agent_id, delegating user, issuer DID, signed JWT
- Badge proves the agent is authorized to act on Sarah's behalf

### 2. Okta XAA Token Exchange (RFC 8693)
- Agent exchanges its badge JWT for domain-specific access tokens
- Each target domain (Open-Meteo, Slack) receives a scoped token
- Implements OAuth 2.0 Token Exchange (`urn:ietf:params:oauth:grant-type:token-exchange`)

### 3. TBAC Middleware (IdentityServiceMCPMiddleware)
- Intercepts every MCP tool call before execution
- Validates badge authenticity and expiration
- Enforces scope alignment (requested ⊆ authorized)
- Checks delegation chain integrity
- Blocks scope escalation attempts

## Project Structure

```
├── agent/                    # Agent orchestrator
│   ├── openclaw_agent.py     # Main agent logic
│   ├── task_context.py       # Delegation chain tracking
│   └── config.py             # Configuration
├── identity/                 # AGNTCY Identity layer
│   ├── badge_issuer.py       # Badge issuance
│   ├── badge_verifier.py     # Badge verification
│   └── okta_xaa.py           # Okta XAA token exchange
├── middleware/                # TBAC enforcement
│   └── agntcy_tbac.py        # IdentityServiceMCPMiddleware
├── mcp_servers/               # MCP server clients
│   ├── weather_mcp.py
│   └── slack_mcp.py
├── tests/                    # Test suite
├── docker-compose.yml
├── Dockerfile
├── .env.example
└── requirements.txt
```

## Quick Start

### Prerequisites
- Python 3.9+
- Docker & Docker Compose (optional, for full stack)
- Okta developer account (for XAA token exchange)
- AGNTCY Identity Service instance

### Local Development

```bash
# Clone and enter the repo
cd xdomain-openclaw-agntcy-poc

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your credentials

# Run tests
pytest tests/ -v

# Run the agent
python -m agent.openclaw_agent
```

### Docker Compose

```bash
# Copy and configure environment
cp .env.example .env

# Start all services
docker-compose up --build

# Run tests in container
docker-compose run openclaw-agent pytest tests/ -v
```

## Auth Flow

1. **Sarah** delegates a task to the OpenClaw agent
2. **Agent** requests an identity badge from AGNTCY Identity Service
3. For each MCP server (Weather, Slack):
   - **Agent** exchanges badge JWT for domain-specific token via Okta XAA
   - **TBAC middleware** validates badge + scopes before the call proceeds
   - **MCP server** receives the scoped token and executes the tool call
4. **Agent** aggregates results and returns them to Sarah

## Delegation Chain Example

```
Sarah (human)
  └─▶ OpenClaw Agent [badge: badge-openclaw-agent-001]
        ├─▶ Weather MCP [xaa-token: api.open-meteo.com, scopes: weather:read]
        └─▶ Slack MCP [xaa-token: slack.com, scopes: slack:chat:write]
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
