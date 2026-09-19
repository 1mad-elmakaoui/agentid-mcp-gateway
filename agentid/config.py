"""Runtime configuration.

Settings are read from the environment (or a ``.env`` file) once and cached.
Nothing in AgentID reads ``os.environ`` directly; everything goes through
:func:`get_settings` so tests can override a single object.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTID_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- general -----------------------------------------------------------
    environment: str = "development"
    debug: bool = False

    # --- storage -----------------------------------------------------------
    database_url: str = "sqlite:///./agentid.db"

    # --- tokens ------------------------------------------------------------
    # Signing key for gateway-issued tokens. MUST be overridden in production.
    secret_key: str = "dev-only-insecure-secret-change-me"
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "agentid"
    # Audience of tokens that clients present to the gateway.
    jwt_audience: str = "agentid-gateway"
    # Audience of the short-lived credentials the gateway mints for downstream
    # MCP servers. Distinct from ``jwt_audience`` so a client token can never be
    # replayed directly against a downstream server.
    downstream_audience_prefix: str = "agentid-mcp"

    access_token_ttl_seconds: int = 3600
    delegated_token_ttl_seconds: int = 900
    downstream_token_ttl_seconds: int = 120
    session_ttl_seconds: int = 86400

    # --- credential vault --------------------------------------------------
    # Key used to encrypt downstream credentials at rest. Falls back to
    # ``secret_key`` when unset, which is fine for development only.
    credential_encryption_key: str | None = None

    # --- proxy -------------------------------------------------------------
    downstream_timeout_seconds: float = 30.0

    # --- rate limiting -----------------------------------------------------
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 120
    rate_limit_window_seconds: int = 60

    # --- policy ------------------------------------------------------------
    # Optional path to a YAML/JSON policy bundle loaded on startup.
    policy_file: str | None = None

    # --- audit -------------------------------------------------------------
    audit_stdout: bool = True

    api_key_prefix: str = Field(default="aid_sk_", min_length=1)

    @property
    def vault_key(self) -> str:
        return self.credential_encryption_key or self.secret_key

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    """Drop the cached settings (used by tests that mutate the environment)."""
    get_settings.cache_clear()
