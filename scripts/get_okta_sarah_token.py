"""
Interactive CLI helper to obtain Sarah's Okta access token via authorization code + PKCE.

Mirrors scripts/get_xaa_id_token.py but targets Okta instead of xaa.dev.
Prints the authorize URL on stderr, captures the callback at
http://localhost:8080/callback, exchanges the code for an access token,
and prints ONLY the access token on stdout.

Usage:
    export SARAH_ACCESS_TOKEN=$(python -m scripts.get_okta_sarah_token 2>/dev/null)

Required env vars:
    OKTA_DOMAIN          e.g. agntcydev1.oktapreview.com
    OKTA_CLIENT_ID       openclaw-agent client id
    OKTA_CLIENT_SECRET   openclaw-agent client secret

Optional:
    OKTA_REDIRECT_URI    defaults to http://localhost:8080/callback
    OKTA_SCOPE           defaults to "openid profile email"
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

logger = logging.getLogger("get_okta_sarah_token")
logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).decode("ascii").rstrip("=")
    return verifier, challenge


class _CallbackResult:
    def __init__(self) -> None:
        self.code: Optional[str] = None
        self.state: Optional[str] = None
        self.error: Optional[str] = None


def _build_handler(result: _CallbackResult, expected_state: str):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *a, **k) -> None:
            pass

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404); self.end_headers(); return
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            if params.get("state") != expected_state:
                result.error = f"state mismatch"
                self.send_response(400); self.end_headers()
                self.wfile.write(b"state mismatch"); return
            if "error" in params:
                result.error = params.get("error_description", params["error"])
                self.send_response(400); self.end_headers()
                self.wfile.write(result.error.encode()); return
            result.code = params.get("code")
            result.state = params.get("state")
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"<h2>Got the code. You can close this tab.</h2>")
    return _Handler


def main() -> int:
    domain = os.environ.get("OKTA_DOMAIN", "").strip()
    client_id = os.environ.get("OKTA_CLIENT_ID", "").strip()
    client_secret = os.environ.get("OKTA_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get("OKTA_REDIRECT_URI", "http://localhost:8080/callback").strip()
    scope = os.environ.get("OKTA_SCOPE", "openid profile email").strip()

    if not (domain and client_id and client_secret):
        logger.error("OKTA_DOMAIN, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET must be set")
        return 1

    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(24)

    authorize_url = f"https://{domain}/oauth2/v1/authorize?" + urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    logger.info("\nSTEP 1 — Open this URL in your browser and sign in as Sarah:")
    logger.info("  %s\n", authorize_url)
    logger.info("Waiting for callback on %s...", redirect_uri)

    parsed = urlparse(redirect_uri)
    port = parsed.port or 8080

    result = _CallbackResult()
    server = HTTPServer(("127.0.0.1", port), _build_handler(result, state))

    def _serve():
        server.handle_request()  # one request and stop

    t = Thread(target=_serve, daemon=True)
    t.start()
    t.join(timeout=300)  # 5 min wait

    if result.error:
        logger.error("Callback error: %s", result.error)
        return 2
    if not result.code:
        logger.error("Timed out waiting for callback")
        return 2

    logger.info("Got authorization code, exchanging for token...")

    token_url = f"https://{domain}/oauth2/v1/token"
    form = {
        "grant_type": "authorization_code",
        "code": result.code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "code_verifier": verifier,
    }

    resp = httpx.post(token_url, data=form, timeout=15)
    if resp.status_code != 200:
        logger.error("Token exchange failed: %s %s", resp.status_code, resp.text)
        return 3

    body = resp.json()
    access_token = body.get("id_token") or body.get("access_token") or ""
    if not access_token:
        logger.error("Response missing access_token: %s", body)
        return 4

    logger.info("Success — printing id_token to stdout.")
    print(access_token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
