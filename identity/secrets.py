"""AWS Secrets Manager helpers for loading Okta and AGNTCY credentials."""
import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


def load_secret(secret_name: str, region: str = "us-east-1") -> Dict[str, Any]:
    """Load a secret from AWS Secrets Manager and return as dict.

    Falls back to empty dict if boto3 is unavailable or secret not found.
    """
    try:
        import boto3
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=secret_name)
        return json.loads(resp["SecretString"])
    except Exception as e:
        logger.warning("Failed to load secret %s: %s", secret_name, e)
        return {}


def load_okta_config(secret_name: str = "xdomain-agntcy-poc/okta") -> Dict[str, str]:
    """Load Okta configuration from Secrets Manager."""
    secret = load_secret(secret_name)
    return {
        "domain": secret.get("domain", ""),
        "client_id": secret.get("client_id", ""),
        "client_secret": secret.get("client_secret", ""),
        "auth_server_id": secret.get("auth_server_id", ""),
        "audience": secret.get("audience", ""),
        "token_endpoint": secret.get("token_endpoint", ""),
        "issuer": secret.get("issuer", ""),
    }


def load_badge_config(secret_name: str = "xdomain-agent-poc/agent-badge") -> Dict[str, str]:
    """Load AGNTCY badge configuration from Secrets Manager."""
    secret = load_secret(secret_name)
    return {
        "well_known": secret.get("well_known", ""),
        "badge_id": secret.get("badge_id", ""),
        "metadata_id": secret.get("metadata_id", ""),
    }
