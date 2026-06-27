"""
Small FastAPI app that serves CIMD documents for AGNTCY-registered agents.

Deployed alongside (not inside) the resource-auth-server so it has no
dependency on Okta env vars: a deployment that only wants CIMD discovery
should not need an IdP configured.

Routes:
  * ``GET /.well-known/cimd/{metadata_id}``
        Returns the CIMD JSON document for the given agent. The
        document's ``client_id`` is set to the absolute URL of this
        endpoint so the self-reference invariant holds when a
        resolver fetches it.
  * ``GET /healthz``
        Liveness probe.

Configuration (all required at start, fail-fast):
  * ``CIMD_BASE_URL``                 — public base URL this server is
        reachable at (e.g. ``http://cimd.localhost:5002``). Combined
        with ``metadata_id`` to form the self-referential ``client_id``.
  * ``AGNTCY_NODE_URL``               — AGNTCY identity node base URL
        (e.g. ``http://localhost:4000``).
  * ``AGNTCY_ISSUER_JWKS_URI``        — JWKS URL of the AGNTCY issuer
        that signed the badge; embedded in the CIMD document so a
        relying party can verify the badge JWT.
  * ``AGENT_CLIENT_NAME``             — human-readable name for the
        agent (e.g. ``OpenClaw Cross-Domain Agent``).
  * ``AGENT_DECLARED_ID``             — agent_id the CIMD document
        DECLARES; the resolver enforces it equals the badge's verified
        ``agent_id`` (Phase-1 fix #4 binding).
  * ``AGENT_DECLARED_USER``           — delegating_user the CIMD
        document declares; same binding rule.

The set of {metadata_id → declared identity} is intentionally
single-tenant in this PoC — one agent per CIMD-server instance. A
multi-tenant deployment would key the declared identity off
``metadata_id`` instead of process-wide env vars; out of scope here.
"""
from __future__ import annotations

import logging
import os
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from identity.cimd_document import (
    CIMDDocumentError,
    CIMDDocumentSpec,
    build_cimd_document_from_agntcy,
    cimd_document_self_url,
)

logger = logging.getLogger("cimd-server")


def _require_env(key: str) -> str:
    value = os.environ.get(key, "").strip()
    if not value:
        raise RuntimeError(f"CIMD server requires env var {key}")
    return value


def _load_config() -> Dict[str, str]:
    return {
        "base_url": _require_env("CIMD_BASE_URL").rstrip("/"),
        "agntcy_node_url": _require_env("AGNTCY_NODE_URL").rstrip("/"),
        "agntcy_jwks_uri": _require_env("AGNTCY_ISSUER_JWKS_URI"),
        "client_name": _require_env("AGENT_CLIENT_NAME"),
        "agent_id": _require_env("AGENT_DECLARED_ID"),
        "delegating_user": _require_env("AGENT_DECLARED_USER"),
    }


def create_app() -> FastAPI:
    """FastAPI app factory.

    Config is loaded lazily inside the route so tests can construct the
    app and override env vars per-test with ``monkeypatch.setenv`` —
    no module-level ``os.environ`` reads at import time.
    """
    app = FastAPI(title="AGNTCY CIMD Server", version="0.1.0")

    @app.get("/healthz")
    def healthz() -> Dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/cimd/{metadata_id}")
    async def cimd_endpoint(metadata_id: str) -> JSONResponse:
        try:
            cfg = _load_config()
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        self_url = cimd_document_self_url(cfg["base_url"], metadata_id)
        spec = CIMDDocumentSpec(
            self_url=self_url,
            client_name=cfg["client_name"],
            agent_id=cfg["agent_id"],
            delegating_user=cfg["delegating_user"],
            jwks_uri=cfg["agntcy_jwks_uri"],
        )

        try:
            document = await build_cimd_document_from_agntcy(
                spec,
                agntcy_node_url=cfg["agntcy_node_url"],
                agntcy_metadata_id=metadata_id,
            )
        except LookupError as exc:
            logger.warning(
                "CIMD doc unavailable for metadata_id=%s: %s",
                metadata_id, exc,
            )
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CIMDDocumentError as exc:
            logger.error("CIMD doc build failed: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return JSONResponse(content=document, media_type="application/json")

    return app


app = create_app()
