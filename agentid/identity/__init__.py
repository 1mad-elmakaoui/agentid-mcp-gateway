"""Identity: users, agents, service accounts, sessions, delegation, tokens."""

from .agents import (
    create_agent,
    get_agent,
    get_agent_by_name,
    grant_agent_to_user,
    list_agents,
    list_user_agents,
    require_agent,
    resolve_agent,
    revoke_agent_from_user,
    user_may_delegate_to,
)
from .api_keys import IssuedApiKey, issue_api_key, revoke_api_key, verify_api_key
from .delegation import (
    DelegationResult,
    delegate,
    describe_chain,
    persona_for,
    require_active_delegation,
    revoke_delegation,
)
from .service_accounts import (
    create_service_account,
    grant_service_account,
    list_grants_for,
    list_service_accounts,
    may_use_service_account,
    require_service_account,
    resolve_service_account,
    revoke_service_account,
)
from .sessions import create_session, require_active_session, revoke_session
from .tokens import TokenClaims, TokenService, TokenType
from .users import authenticate_user, create_user, get_user_by_email, list_users, require_user

__all__ = [
    "DelegationResult",
    "IssuedApiKey",
    "TokenClaims",
    "TokenService",
    "TokenType",
    "authenticate_user",
    "create_agent",
    "create_service_account",
    "create_session",
    "create_user",
    "delegate",
    "describe_chain",
    "get_agent",
    "get_agent_by_name",
    "get_user_by_email",
    "grant_agent_to_user",
    "grant_service_account",
    "issue_api_key",
    "list_agents",
    "list_grants_for",
    "list_service_accounts",
    "list_user_agents",
    "list_users",
    "may_use_service_account",
    "persona_for",
    "require_active_delegation",
    "require_active_session",
    "require_agent",
    "require_service_account",
    "require_user",
    "resolve_agent",
    "resolve_service_account",
    "revoke_agent_from_user",
    "revoke_api_key",
    "revoke_delegation",
    "revoke_service_account",
    "revoke_session",
    "user_may_delegate_to",
    "verify_api_key",
]
