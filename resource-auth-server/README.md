# Resource Authorization Server (XAA PoC)

FastAPI authorization server that participates in a Cross App Access (XAA)
flow by validating ID-JAG assertions issued by Okta and minting local access
tokens for the protected resource.

## Role in the XAA flow

1. An agent (e.g., OpenClaw) holds an ID-JAG (`urn:ietf:params:oauth:grant-type:jwt-bearer`)
   assertion issued by Okta on behalf of a human user.
2. The agent POSTs the assertion to this server's `/oauth2/token` endpoint.
3. The server:
   - Fetches and caches Okta's JWKS (`{OKTA_ISSUER}/oauth2/v1/keys`, TTL 1h).
   - Verifies the ID-JAG signature, `iss`, `aud`, `client_id`/`azp`, and `sub`.
   - Issues a short-lived HS256 access token scoped to this resource.
4. The agent presents the access token to the resource API.

## Endpoints

| Method | Path                                         | Purpose                              |
| ------ | -------------------------------------------- | ------------------------------------ |
| GET    | `/healthz`                                   | Liveness check                       |
| GET    | `/.well-known/oauth-authorization-server`    | RFC 8414 server metadata             |
| POST   | `/oauth2/token`                              | ID-JAG → access token exchange       |

## Setup

```bash
cd resource-auth-server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Edit .env and set LOCAL_SIGNING_KEY to a random value, e.g.:
#   python3 -c 'import secrets; print(secrets.token_urlsafe(48))'

uvicorn main:app --host 0.0.0.0 --port 5001 --reload
```

## curl example

```bash
curl -s -X POST http://localhost:5001/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  --data-urlencode "assertion=<ID-JAG JWT from Okta>" \
  --data-urlencode "client_id=openclaw-agent"
```

Successful response:

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read"
}
```

Failure responses follow the OAuth 2.0 error format:

```json
{ "error": "invalid_grant", "error_description": "assertion missing sub claim" }
```

## Docker

```bash
docker build -t xaa-resource-auth-server .
docker run --rm -p 5001:5001 --env-file .env xaa-resource-auth-server
```

## Security notes

- Access tokens are signed with HS256 using a shared secret. **PoC only.**
  Production should use RS256 with a dedicated key pair and publish a JWKS
  endpoint so resource servers can verify tokens without sharing secrets.
- `LOCAL_SIGNING_KEY` must never be logged or committed.
- JWKS is cached in-process; multi-replica deployments should use a shared
  cache or rely on HTTP caching headers.
