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
│  │ (Identity)   │  │  (ID-JAG)        │  │ (IdentityService     │ │
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
## End to End Flow 

1. Sarah delegates task to OpenClaw agent
       ↓
2. Agent fetches AGNTCY badge from identity node
   GET http://13.222.140.133:4000/v1alpha1/vc/AGNTCY-ffe62877.../.well-known/vcs.json
       ↓
3. Agent verifies badge cryptographically
   POST http://13.222.140.133:4000/v1alpha1/vc/verify
   → status: true 
       ↓
4. Agent requests ID-JAG from Okta
   POST https://agntcydev1.oktapreview.com/oauth2/ausd9v0ra5BWoW1y40x7/v1/token
   → scoped access token for weather:read
       ↓
5. TBAC middleware intercepts MCP tool call
   → verifies badge capabilities match requested scopes
   → verifies task == "weather_slack_notification"
   → ALLOW 
       ↓
6. Weather MCP calls Open-Meteo API
   GET https://api.open-meteo.com/v1/forecast?...
   → returns weather data for Austin, TX
       ↓
7. TBAC middleware intercepts Slack MCP call
   → same checks for slack:chat:write
   → ALLOW 
       ↓
8. Slack MCP posts weather summary to #agent-weather-alerts
   
## Layers

### 1. AGNTCY Identity Badge
- The agent obtains a verifiable identity badge from the AGNTCY Identity Service
- Badge contains: agent_id, delegating user, issuer DID, signed JWT
- Badge proves the agent is authorized to act on Sarah's behalf

### 2. Okta XAA — Identity Assertion Authorization Grant (ID-JAG)
- Agent uses Okta's ID-JAG flow to obtain identity assertions, then exchanges them (with AGNTCY badge as actor proof) for scoped access tokens to target MCP servers
- Each target domain (Open-Meteo, Slack) receives a scoped token

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
│   ├── okta_xaa.py           # Okta XAA token exchange (ID-JAG)
│   └── secrets.py            # AWS Secrets Manager helpers
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
- Okta developer account (for XAA ID-JAG token exchange)
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
2. **Agent** requests an identity badge from AGNTCY Identity Service (well-known endpoint)
3. For each MCP server (Weather, Slack):
   - **Agent** requests ID-JAG from Okta (client_credentials)
   - **Agent** exchanges ID-JAG + badge JWT for scoped access token (ID-JAG grant)
   - **TBAC middleware** validates badge + scopes
   - **MCP server** receives the scoped token and executes the tool call
4. **Agent** aggregates results and returns them to Sarah

> All credentials (Okta, AGNTCY badge, Slack) are loaded from AWS Secrets Manager at runtime.

## Delegation Chain Example

```
Sarah (human)
  └─▶ OpenClaw Agent [badge: badge-openclaw-agent-001]
        ├─▶ Weather MCP [xaa-token: api.open-meteo.com, scopes: weather:read]
        └─▶ Slack MCP [xaa-token: slack.com, scopes: slack:chat:write]
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
