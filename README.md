# Cross-Domain Agent Identity PoC

> A working proof-of-concept for cross-domain AI agent identity, combining **AGNTCY identity attestation** (W3C Verifiable Credentials) with **Cross App Access** (RFC 8693 token exchange / IETF ID-JAG). 

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## What This Demonstrates

An OpenClaw agent performs cross-domain tasks (read weather, post to a specific Slack channel) on behalf of a delegating user (Sarah), with two layers of trust:

**Capability layer** — AGNTCY-issued W3C Verifiable Credential (badge) attests the agent's identity and capabilities, signed and cryptographically verifie.

**Scope layer** — IETF Identity Assertion JWT Authorization Grant (ID-JAG, Okta XAA) issues scoped access tokens via the enterprise IdP, validated at a self-hosted resource authorization server

Both layers enforced independently. Channel-bound scopes (`slack.post.agent-weather-alerts`, not `slack.post`). Subject propagation end-to-end for audit. This was tested on XAA.dev and an Okta XAA preview environment.
---
## Architecture
<img width="971" height="681" alt="Screenshot 2026-04-22 at 9 21 31 PM" src="https://github.com/user-attachments/assets/c65135d5-0a50-48bf-b82e-203ec415fcfd" />

## End-to-End Flow (6 Steps)

1. **Badge fetch** — Orchestrator fetches the AGNTCY badge (W3C VC, JWT-encoded) from the identity node's well-known endpoint
2. **Badge verify** — Orchestrator verifies the badge cryptographically against the AGNTCY identity node
3. **ID-JAG exchange** — Orchestrator exchanges Sarah's IdP ID token for an ID-JAG via RFC 8693 token exchange. The AGNTCY badge is sent as `actor_token`. *(See "Empirical Findings" below for what this proves.)*
4. **Access token mint** — Resource authorization server validates the ID-JAG against IdP JWKS, mints a scoped access token bound to the agent and requested scopes
5. **TBAC enforcement** — Middleware re-verifies the badge, checks badge capability ⨯ requested scope alignment, validates target domain authorization. ALLOW or DENY before tool dispatch.
6. **Tool execution** — MCP layer dispatches authorized tool calls (weather read + Slack post). Subject claim from access token propagates into every tool invocation for audit.

**Two-instance deployment:**

- **Lightsail #1**  — AGNTCY identity node (port 4000) + OpenClaw orchestrator 
- **Lightsail #2**  — Resource authorization server (validates ID-JAGs, mints access tokens)

## Two-layer enforcement

The PoC demonstrates **independent failure domains** for authorization:

| Layer | Authority | Carries | Enforced at |
|---|---|---|---|
| Capability | AGNTCY identity node | Badge JWT (capabilities) | TBAC middleware |
| Scope | IdP (xaa.dev or Okta) | Access token (OAuth scopes) | Resource auth server + middleware |

Compromise of one layer does not collapse the other. The badge says "this agent
*may* do these things"; the access token says "this token *carries permission*
to do these things at this resource." Both are required.

## Path A: xaa.dev IdP

### Setup

1. **Register an app** at https://xaa.dev. You'll receive four credentials:
   - Main (IdP) client ID + secret
   - Resource client ID + secret (shape: `{client_id}-at-res_{uuid}`)

2. **Configure the resource app** at xaa.dev:
   - Resource Identifier URL: your resource auth server's audience identifier
   - MCP scopes: `weather.read`, `slack.post.agent-weather-alerts`
   - MCP Resource URIs and Tools as needed

3. **Export env vars** (Lightsail #1):
```bash
   export USE_XAA_DEV=true
   export XAA_CLIENT_ID=<main-client-id>
   export XAA_CLIENT_SECRET=<main-client-secret>
   export XAA_RESOURCE_CLIENT_ID=<resource-client-id>
   export XAA_RESOURCE_CLIENT_SECRET=<resource-client-secret>
   export XAA_RESOURCE_AUDIENCE=http://weather-slack-resources.com
   export SLACK_CHANNEL=agent-weather-alerts
   export SLACK_BOT_TOKEN=<xoxb-...>
```

4. **Bootstrap Sarah's ID token**:
```bash
   export XAA_ID_TOKEN=$(python -m scripts.get_xaa_id_token)
```

5. **Run the demo**:
```bash
   python -m agent.xaa_orchestrator --demo
```

## Path B: Okta tenant IdP

### Prerequisites

- Okta tenant with **Cross App Access (EA)** enabled
- **Agent0** (Cross App Access Sample Requesting App) catalog app installed → represents the openclaw-agent
- **Todo0** (Cross App Access Sample Resource App) catalog app installed → represents the resource (weather-slack-resources)
- Test user assigned to both apps
- Manage Connections established bidirectionally on both apps ("App granted consent" + "Apps providing consent")

### Setup

1. **Configure Okta apps:**
   - Agent0 redirect URI: `http://localhost:8080/callback`
   - Todo0 redirect URI: `http://localhost:5001/openid/callback/customer1`

2. **Configure the resource auth server** (Lightsail #2 — `resource-auth-server/.env`):
OKTA_ISSUER=https://<your-tenant>.oktapreview.com
RESOURCE_AUDIENCE=http://localhost:5001
REGISTERED_CLIENT_ID=wiki0-at-todo0
LOCAL_SIGNING_KEY=<random-secret>
ACCESS_TOKEN_TTL=3600
   Restart: `sudo systemctl restart resource-auth-server.service`

3. **Export env vars** (Lightsail #1):
```bash
   export USE_XAA_DEV=false
   export OKTA_DOMAIN=<your-tenant>.oktapreview.com
   export ORG2_DOMAIN=<your-tenant>.oktapreview.com
   export OKTA_CLIENT_ID=<Agent0 client id>
   export OKTA_CLIENT_SECRET=<Agent0 client secret>
   export WEATHER_AUDIENCE=http://localhost:5001
   export SLACK_AUDIENCE=http://localhost:5001
   export RESOURCE_AUTH_CLIENT_ID=wiki0-at-todo0
   export DELEGATING_USER=<your-test-user>@example.com
   export SLACK_CHANNEL=agent-weather-alerts
   export SLACK_BOT_TOKEN=<xoxb-...>
```

4. **Bootstrap Sarah's ID token** (Authorization Code + PKCE against Okta org auth server):
```bash
   sudo lsof -ti:8080 | xargs -r sudo kill -9 2>/dev/null
   python -m scripts.get_okta_sarah_token
   export SARAH_ACCESS_TOKEN="<paste eyJ... JWT>"
```

5. **Run the demo**:
```bash
   python -m agent.xaa_orchestrator --demo
```

### Path B caveats

The PoC currently uses Okta's catalog Todo0 placeholder defaults rather than
custom-registered audience and client_id values. This is because the
tenant-side audience override (managed by Okta's XAA team) is pending. As a
result:

- **Audience claim** in the ID-JAG is `http://localhost:5001` (the Todo0 catalog
  default), not the resource auth server's actual public URL. The resource auth
  server is configured to accept this audience to complete the flow.
- **Client identity** in the ID-JAG is `wiki0-at-todo0` (Okta's catalog-baked
  resource-side client identifier for the Agent0→Todo0 sample pair), not openclaw-agent's name.

The **cryptographic trust chain is intact** (Okta signs, resource auth server
verifies against Okta's JWKS, audience matching enforced). The placeholder
labels are a documented limitation of using catalog placeholder apps and would
be replaced with real values via Okta XAA team configuration in a production
deployment.

## Project Structure
| Path | Purpose |
|------|---------|
| `agent/xaa_orchestrator.py` | 6-step XAA flow orchestrator |
| `agent/config.py` | `AgentConfig` env var loader |
| `identity/badge_issuer.py` | AGNTCY badge fetch from well-known endpoint |
| `identity/badge_verifier.py` | AGNTCY badge cryptographic verification |
| `identity/xaa_dev_client.py` | **Path A** — xaa.dev IdP token exchange |
| `identity/okta_xaa.py` | **Path B** — Okta IdP token exchange |
| `identity/resource_exchange.py` | ID-JAG → access token redemption at resource auth server |
| `middleware/agntcy_tbac.py` | TBAC enforcement (badge.capabilities ⨯ token.scopes ⨯ task) |
| `mcp_servers/weather_mcp.py` | Open-Meteo tool dispatcher |
| `mcp_servers/slack_mcp.py` | Slack `chat.postMessage` tool dispatcher |
| `resource-auth-server/main.py` | Standalone resource auth server (Lightsail #2) |
| `scripts/get_xaa_id_token.py` | Sarah's ID token bootstrap — Path A |
| `scripts/get_okta_sarah_token.py` | Sarah's ID token bootstrap — Path B |
| `tests/` | Unit + integration tests |
| `docs/xaa-flow.png` | Architecture diagram |
| `requirements.txt` | Python dependencies |
| `.env.example` | Env var template |


## Resource API enforcement (open work)

Open-Meteo and Slack are **not XAA-enabled** in this PoC — the access token
is enforced at the orchestrator/MCP middleware layer rather than at the
resource API itself. This is documented as a scoping decision: the contribution
of this PoC is the agent trust boundary (badge + scope) up to the access token. Closing the last hop would require either:

- A mock XAA-enabled resource service (e.g., Auth0's XAA resource Beta), or
- Native XAA support in the target API

## License

Apache 2.0 — see [LICENSE](LICENSE).
