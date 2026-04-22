"""
Interactive CLI helper to obtain Sarah's ID token from xaa.dev.

Runs the Step 1A browser authorize + Step 1B code exchange flow locally:
prints the authorize URL (open it in a browser, sign in as Sarah), then
captures the redirect at ``http://localhost:8000/callback`` and exchanges
the code for an ID token using PKCE.

stdout gets ONLY the ID token on success — so the caller can do:

    export XAA_ID_TOKEN=$(python -m scripts.get_xaa_id_token 2>/dev/null)

stderr gets the human-readable progress narration.

Required env vars:
    XAA_CLIENT_ID       main (IdP) client id registered at xaa.dev
    XAA_CLIENT_SECRET   main (IdP) client secret

Optional env vars:
    XAA_IDP_URL         defaults to https://idp.xaa.dev
    XAA_REDIRECT_URI    defaults to http://localhost:8000/callback
    XAA_SCOPE           defaults to "openid email"
"""
from __future__ import annotations

import asyncio
import logging
import os
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from identity.xaa_dev_client import (
    XAADevClient,
    XAADevConfig,
    XAADevError,
    generate_pkce_pair,
)

logger = logging.getLogger("get_xaa_id_token")


class _CallbackResult:
    """Mutable shared state between the HTTP handler and the main thread."""

    def __init__(self) -> None:
        self.code: Optional[str] = None
        self.state: Optional[str] = None
        self.error: Optional[str] = None


def _build_handler(result: _CallbackResult, expected_state: str):
    class _CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — http.server requires this name
            parsed = urlparse(self.path)
            if parsed.path != "/callback":
                self.send_response(404)
                self.end_headers()
                return

            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            got_state = params.get("state", "")
            if got_state != expected_state:
                result.error = (
                    f"state mismatch: expected {expected_state!r}, "
                    f"got {got_state!r}"
                )
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"state mismatch")
                return

            if "error" in params:
                result.error = params.get(
                    "error_description", params["error"]
                )
                self.send_response(400)
                self.end_headers()
                self.wfile.write(result.error.encode("utf-8"))
                return

            code = params.get("code")
            if not code:
                result.error = "callback missing ?code= param"
                self.send_response(400)
                self.end_headers()
                self.wfile.write(result.error.encode("utf-8"))
                return

            result.code = code
            result.state = got_state
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body><h2>XAA code received.</h2>"
                b"<p>You can close this tab and return to the terminal.</p>"
                b"</body></html>"
            )

        def log_message(self, fmt: str, *args) -> None:  # silence stdlib
            return

    return _CallbackHandler


def _build_config_from_env() -> XAADevConfig:
    client_id = os.environ.get("XAA_CLIENT_ID", "")
    client_secret = os.environ.get("XAA_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise SystemExit(
            "XAA_CLIENT_ID and XAA_CLIENT_SECRET must be set to "
            "register an app at https://xaa.dev and fetch its credentials."
        )
    return XAADevConfig(
        idp_url=os.environ.get("XAA_IDP_URL", "https://idp.xaa.dev"),
        auth_server_url=os.environ.get(
            "XAA_AUTH_SERVER_URL", "https://auth.resource.xaa.dev"
        ),
        client_id=client_id,
        client_secret=client_secret,
        resource_client_id=os.environ.get("XAA_RESOURCE_CLIENT_ID", ""),
        resource_client_secret=os.environ.get("XAA_RESOURCE_CLIENT_SECRET", ""),
        redirect_uri=os.environ.get(
            "XAA_REDIRECT_URI", "http://localhost:8000/callback"
        ),
        resource_audience=os.environ.get("XAA_RESOURCE_AUDIENCE", ""),
        scope=os.environ.get("XAA_SCOPE", "openid email"),
    )


def _wait_for_callback(result: _CallbackResult, expected_state: str,
                       port: int) -> None:
    """Run the single-shot callback server until a request arrives."""
    handler_cls = _build_handler(result, expected_state)
    server = HTTPServer(("127.0.0.1", port), handler_cls)
    logger.info(
        "Listening for xaa.dev callback on http://localhost:%d/callback ...",
        port,
    )
    try:
        while result.code is None and result.error is None:
            server.handle_request()
    finally:
        server.server_close()


async def _run() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(message)s", stream=sys.stderr,
    )
    config = _build_config_from_env()
    client = XAADevClient(config)

    verifier, challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(24)

    authorize_url = await client.build_authorize_url(
        state=state, code_challenge=challenge,
    )

    logger.info("")
    logger.info("STEP 1A — Open this URL in your browser and sign in:")
    logger.info("  %s", authorize_url)
    logger.info("")
    logger.info("Waiting for callback...")

    redirect_port = int(urlparse(config.redirect_uri).port or 8000)
    result = _CallbackResult()
    thread = Thread(
        target=_wait_for_callback,
        args=(result, state, redirect_port),
        daemon=True,
    )
    thread.start()
    while thread.is_alive():
        await asyncio.sleep(0.2)

    if result.error:
        logger.error("Callback error: %s", result.error)
        return 1
    assert result.code is not None

    logger.info("STEP 1B — Exchanging authorization code for ID token...")
    try:
        token_response: Dict = await client.exchange_code_for_id_token(
            code=result.code, code_verifier=verifier,
        )
    except XAADevError as exc:
        logger.error("Code exchange failed: %s", exc)
        return 2

    id_token = token_response.get("id_token", "")
    if not id_token:
        logger.error(
            "Token response missing id_token; keys: %s",
            list(token_response.keys()),
        )
        return 3

    logger.info("Success — printing ID token to stdout.")
    print(id_token)
    return 0


def main() -> int:
    try:
        return asyncio.run(_run())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
