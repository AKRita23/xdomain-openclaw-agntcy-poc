#!/usr/bin/env bash
# refresh_sarah_token.sh — Obtain Sarah's access token from openclaw-agent
# using the Okta DEFAULT auth server (org-level, not custom).
#
# Usage:
#   source scripts/refresh_sarah_token.sh
#   # → sets SARAH_ACCESS_TOKEN in current shell
#
#   # or capture directly:
#   export SARAH_ACCESS_TOKEN=$(bash scripts/refresh_sarah_token.sh)
#
# Required env vars:
#   SARAH_USERNAME  — Sarah's Okta username  (e.g. sarah@agntcydev1.com)
#   SARAH_PASSWORD  — Sarah's Okta password
set -euo pipefail

TOKEN_ENDPOINT="https://agntcydev1.oktapreview.com/oauth2/v1/token"

# openclaw-agent (catalog app) credentials
CLIENT_ID="0oad9x2gnbmQOy1lC0x7"
CLIENT_SECRET="bLP9c3jetIczK1rg-mqfKMCseFRLw8KxgCfZdGmWDBfEI7xQeyBmmV-Q33H9hEfI"

SCOPE="openid profile email"

: "${SARAH_USERNAME:?Set SARAH_USERNAME}"
: "${SARAH_PASSWORD:?Set SARAH_PASSWORD}"

response=$(curl -s -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "username=${SARAH_USERNAME}" \
  -d "password=${SARAH_PASSWORD}" \
  -d "scope=${SCOPE}")

error=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error',''))" 2>/dev/null || true)
if [ -n "$error" ]; then
  desc=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('error_description',''))" 2>/dev/null || true)
  echo "Error: ${error} — ${desc}" >&2
  exit 1
fi

token=$(echo "$response" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
if [ -z "$token" ]; then
  echo "Failed to extract access_token from response" >&2
  echo "$response" >&2
  exit 1
fi

# If sourced, export; if run as subprocess, print to stdout
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "$token"
else
  export SARAH_ACCESS_TOKEN="$token"
  echo "SARAH_ACCESS_TOKEN set (${#token} chars)" >&2
fi
