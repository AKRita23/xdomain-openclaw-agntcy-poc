/**
 * get_xaa_token.mjs — Okta XAA ID-JAG flow (single-org, managed connection).
 *
 * Both steps hit the Org 1 DEFAULT auth server token endpoint.
 *
 *   Step 1: requestIdJwtAuthzGrant
 *           openclaw-agent creds + Sarah's access token → ID-JAG
 *
 *   Step 2: exchangeIdJwtAuthzGrant
 *           weather-slack-resources creds + ID-JAG → scoped access token
 *
 * Required env vars:
 *   SARAH_ACCESS_TOKEN          — Sarah's access token (from refresh_sarah_token.sh)
 *   RESOURCE_APP_CLIENT_SECRET  — weather-slack-resources client secret
 *
 * Optional env vars:
 *   XAA_SCOPE                   — scope to request (default: weather:read)
 */

import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const {
  requestIdJwtAuthzGrant,
  exchangeIdJwtAuthzGrant,
} = require("./lib/id-assert-authz-grant-client.cjs");

// ── Config ───────────────────────────────────────────────────────────────────

// Org 1 default auth server (NOT the custom auth server)
const TOKEN_ENDPOINT =
  "https://agntcydev1.oktapreview.com/oauth2/v1/token";

// openclaw-agent (requesting app / actor)
const OPENCLAW_CLIENT_ID = "0oad9x2gnbmQOy1lC0x7";
const OPENCLAW_CLIENT_SECRET =
  "bLP9c3jetIczK1rg-mqfKMCseFRLw8KxgCfZdGmWDBfEI7xQeyBmmV-Q33H9hEfI";

// weather-slack-resources (resource app)
const RESOURCE_CLIENT_ID = "0oadd7bntwQe9XiL90x7";
const RESOURCE_CLIENT_SECRET = requireEnv("RESOURCE_APP_CLIENT_SECRET");

const AUDIENCE = "https://xdomain-agent.agentex.io";
const SCOPE = process.env.XAA_SCOPE || "weather:read";

const SARAH_TOKEN = requireEnv("SARAH_ACCESS_TOKEN");

// ── Helpers ──────────────────────────────────────────────────────────────────

function requireEnv(name) {
  const val = process.env[name];
  if (!val) {
    console.error(`Error: ${name} is not set`);
    process.exit(1);
  }
  return val;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  // Step 1 — Request ID-JAG assertion from Org 1
  console.log("Step 1: Requesting ID-JAG from Org 1 …");
  console.log(`  token_url         : ${TOKEN_ENDPOINT}`);
  console.log(`  client_id (actor) : ${OPENCLAW_CLIENT_ID}`);
  console.log(`  audience          : ${AUDIENCE}`);
  console.log(`  scope             : ${SCOPE}`);

  const jagResult = await requestIdJwtAuthzGrant({
    tokenUrl: TOKEN_ENDPOINT,
    audience: AUDIENCE,
    subjectTokenType: "access_token",
    subjectToken: SARAH_TOKEN,
    scopes: [SCOPE],
    clientID: OPENCLAW_CLIENT_ID,
    clientSecret: OPENCLAW_CLIENT_SECRET,
  });

  if ("error" in jagResult) {
    console.error("Step 1 failed:", JSON.stringify(jagResult.error, null, 2));
    process.exit(1);
  }

  const idJag = jagResult.payload.access_token;
  console.log("Step 1 OK — ID-JAG received");
  console.log(`  issued_token_type : ${jagResult.payload.issued_token_type}`);

  // Step 2 — Exchange ID-JAG for scoped access token (same Org 1 endpoint)
  console.log("\nStep 2: Exchanging ID-JAG for access token …");
  console.log(`  token_url          : ${TOKEN_ENDPOINT}`);
  console.log(`  client_id (resource): ${RESOURCE_CLIENT_ID}`);
  console.log(`  audience           : ${AUDIENCE}`);
  console.log(`  scope              : ${SCOPE}`);

  const tokenResult = await exchangeIdJwtAuthzGrant({
    tokenUrl: TOKEN_ENDPOINT,
    authorizationGrant: idJag,
    scopes: [SCOPE],
    audience: AUDIENCE,
    clientID: RESOURCE_CLIENT_ID,
    clientSecret: RESOURCE_CLIENT_SECRET,
  });

  if ("error" in tokenResult) {
    console.error("Step 2 failed:", JSON.stringify(tokenResult.error, null, 2));
    process.exit(1);
  }

  const accessToken = tokenResult.payload.access_token;
  console.log("Step 2 OK — scoped access token received");
  console.log(`  token_type : ${tokenResult.payload.token_type}`);
  console.log(`  expires_in : ${tokenResult.payload.expires_in}`);
  console.log(`  scope      : ${tokenResult.payload.scope ?? "(none)"}`);

  // Print token for capture via $(node scripts/get_xaa_token.mjs 2>/dev/null)
  console.log("\n── Access Token ──");
  console.log(accessToken);
}

main();
