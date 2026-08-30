# AgentID Architecture

> Zero-Trust Identity & Security Gateway for MCP Agents

## 1. Overview

AgentID is a centralized identity, authentication, authorization, and governance gateway for AI agents using the Model Context Protocol (MCP).

Instead of implementing authentication independently in every MCP server, AgentID provides a single governed entry point for MCP clients and agents.

The gateway is responsible for:

- Authentication
- User identity
- Agent identity
- Service-account identity
- Authorization
- Identity delegation
- Credential resolution
- MCP server aggregation
- Tool discovery
- Audit logging
- Observability
- Rate limiting

Downstream MCP servers are responsible primarily for:

- Verifying gateway-issued credentials
- Enforcing resource-level authorization
- Executing tools
- Returning results

This follows the central gateway architecture described in the MCP authentication paper: heterogeneous clients authenticate once at the gateway, while downstream servers verify credentials issued by the gateway.

---

# 2. Goals

AgentID is designed to solve the following problems:

### Authentication

Provide one authentication layer for heterogeneous MCP clients.

### Identity

Distinguish between:

- Human users
- AI agents
- Autonomous agents
- Service accounts

### Authorization

Determine whether an identity is allowed to access a particular MCP server or tool.

### Delegation

Represent:

```text
User → Agent → Tool
```

without losing either the user's identity or the agent's identity.

### Credential Management

Resolve and attach downstream credentials without exposing them to the agent.

### Governance

Provide a centralized audit trail for every MCP operation.

### Tool Discovery

Aggregate many MCP servers without exposing hundreds of irrelevant tool schemas to an agent.

---

# 3. High-Level Architecture

```text
                         ┌──────────────────────────┐
                         │        AI CLIENTS        │
                         │                          │
                         │ Web / Desktop / CLI      │
                         │ Agent SDKs / Workflows   │
                         └────────────┬─────────────┘
                                      │
                                      │ MCP
                                      ▼
              ┌───────────────────────────────────────────┐
              │              AGENTID GATEWAY              │
              │                                           │
              │  ┌─────────────────────────────────────┐  │
              │  │ Authentication                      │  │
              │  │ OAuth / PKCE / Device / Machine    │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ Identity                            │  │
              │  │ User / Agent / Service Account      │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ Authorization                       │  │
              │  │ RBAC / Policies / Permissions       │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ Delegation                          │  │
              │  │ User → Agent                        │  │
              │  │ User → Service Account              │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ Credential Manager                  │  │
              │  │ OAuth / API Keys / Token Exchange   │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ MCP Registry + Tool Search          │  │
              │  └──────────────────┬──────────────────┘  │
              │                     │                     │
              │  ┌──────────────────▼──────────────────┐  │
              │  │ MCP Proxy / Router                 │  │
              │  └───────────────┬───────┬─────────────┘  │
              │                  │       │                │
              │  ┌───────────────▼──┐ ┌──▼─────────────┐  │
              │  │ Audit / Metrics  │ │ Rate Limiting  │  │
              │  └──────────────────┘ └────────────────┘  │
              └─────────────────────┬─────────────────────┘
                                    │
                       Gateway-issued credentials
                                    │
               ┌────────────────────▼─────────────────────┐
               │               MCP SERVERS                │
               │                                           │
               │ GitHub MCP │ PostgreSQL │ Kubernetes MCP │
               │                                           │
               │      Gateway credential verification      │
               └───────────────────────────────────────────┘
```

---

# 4. Core Components

## 4.1 Gateway

The gateway is the central entry point.

Responsibilities:

```text
Client
  ↓
Authenticate
  ↓
Resolve identity
  ↓
Authorize
  ↓
Resolve credentials
  ↓
Discover / route tool
  ↓
Forward MCP request
  ↓
Audit
  ↓
Return response
```

The gateway should not contain business logic belonging to downstream systems.

---

# 4.2 Authentication

Authentication answers:

> Who is making this request?

Supported authentication mechanisms should evolve in stages.

### MVP

- JWT validation
- API keys for machine agents
- Basic session handling

### Later

- OAuth 2.0
- Authorization Code + PKCE
- Device Code
- Token introspection
- RFC 8693 token exchange

The architecture supports two primary caller personas:

```text
                 ┌───────────────┐
                 │    Persona    │
                 └───────┬───────┘
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
           USER                  NON-USER
        Human-driven            Autonomous
              │                     │
        OAuth / PKCE          Service Account
```

The persona distinction is a security boundary.

A non-user identity must never obtain a user-scoped identity merely because it is operating an AI agent.

---

# 4.3 Identity

AgentID maintains three primary identity types.

```text
User
 │
 ├── owns / operates
 │
 ▼
Agent
 │
 └── may execute through
       │
       ▼
Service Account
```

### User

Represents a human identity.

Example:

```json
{
  "id": "user_123",
  "email": "user@example.com"
}
```

### Agent

Represents an AI agent or application.

Example:

```json
{
  "id": "agent_coding",
  "name": "coding-agent",
  "type": "agent"
}
```

### Service Account

Represents a machine identity used for autonomous execution.

Example:

```json
{
  "id": "sa_prod_deployer",
  "name": "production-deployer"
}
```

---

# 5. Identity Relationships

AgentID must explicitly model relationships between identities.

```text
                    USER
                     │
                     │ authorizes
                     ▼
                   AGENT
                     │
                     │ requests
                     ▼
                   TOOL
                     │
                     │ executes through
                     ▼
              SERVICE ACCOUNT
```

An agent should never automatically inherit every permission of a user.

The effective permission is:

```text
Effective Permissions
    =
User Permissions
    ∩
Agent Permissions
```

The agent must not exceed the user's authorization.

---

# 6. Authorization

Authentication establishes identity.

Authorization determines whether that identity is allowed to perform an operation.

These must remain separate.

```text
Authentication
      │
      ▼
Who are you?
      │
      ▼
Authorization
      │
      ▼
Are you allowed to do this?
```

## Two Authorization Layers

### Gateway Authorization

The gateway answers:

> May this identity access this MCP server or tool?

Examples:

```text
user.role = developer
tool = github.create_issue

→ ALLOW
```

```text
user.role = developer
tool = kubernetes.delete_namespace

→ DENY
```

### Downstream Authorization

The downstream system answers:

> May this identity access this specific resource?

For example:

```text
Gateway
  ↓
"User may use GitHub"

GitHub
  ↓
"User may modify repository X"
```

The gateway should not attempt to reproduce every downstream resource-level permission.

---

# 7. Policy Engine

The policy engine evaluates:

```text
identity
    +
persona
    +
agent
    +
tool
    +
server
    +
requested action
    +
resource
    ↓
authorization decision
```

Example policy:

```yaml
role: developer

allow:
  - github.read
  - github.create_issue
  - database.read

deny:
  - kubernetes.delete_namespace
  - database.drop
  - production.deploy
```

The policy engine returns a structured decision:

```json
{
  "decision": "deny",
  "reason": "missing_permission",
  "policy": "developer"
}
```

---

# 8. User → Service Account

This is one of the most important security flows.

A user may trigger a tool that executes under a service account only if the user is explicitly authorized to use that service account.

```text
User Session
     │
     ▼
Resolve User
     │
     ▼
Does User Have Service Account Access?
     │
     ├─────────────── NO ──────────────┐
     │                                ▼
     │                           403 Forbidden
     │                                │
     │                              Audit
     │
     └────────────── YES
                │
                ▼
       Attach Service Credential
                │
                ▼
            MCP Server
```

The service-account credential must never be supplied by the client.

The gateway owns credential resolution.

Audit records must capture:

```text
human_user
execution_identity
agent
tool
decision
```

---

# 9. Autonomous Agent

An autonomous agent has no human user in the execution chain.

Example:

```text
02:00
  │
  ▼
Security Agent
  │
  ▼
AgentID
  │
  ▼
Service Account
  │
  ▼
Kubernetes MCP
```

The identity should remain:

```json
{
  "persona": "non-user",
  "agent": "security-agent",
  "execution_identity": "security-service-account"
}
```

It must not become:

```json
{
  "user": "some-human"
}
```

simply because the agent needs access to a resource.

---

# 10. Delegation

For a user-driven agent:

```text
User
  │
  │ asks agent to act
  ▼
Agent
  │
  │ calls gateway
  ▼
AgentID
  │
  ▼
MCP Tool
```

AgentID must preserve both identities.

The delegated token should conceptually contain:

```json
{
  "sub": "user_123",
  "act": {
    "sub": "coding-agent"
  },
  "aud": "agentid-gateway",
  "scope": "mcp:tools"
}
```

Where:

- `sub` = user
- `act.sub` = acting agent
- `aud` = intended gateway
- `scope` = permitted MCP scope

This enables auditing:

```text
User:  Imad
Agent: coding-agent
Tool:  github.create_issue
```

instead of simply:

```text
User: Imad
```

---

# 11. Token Architecture

The long-term token flow is:

```text
                  User Token
                      │
                      ▼
                    Agent
                      │
                      │ RFC 8693
                      ▼
               AgentID Token
                      │
              ┌───────┴────────┐
              │                │
          sub = user       act = agent
              │                │
              └───────┬────────┘
                      ▼
                 MCP Server
```

AgentID should eventually support:

```text
BYOT
Bring Your Own Token

GYOT
Generate Your Own Token

Delegated OAuth
RFC 8693
```

These should be implemented progressively rather than all at once.

---

# 12. Credential Manager

Credentials belong to AgentID.

The client should not receive downstream secrets.

```text
Client
  │
  │ MCP request
  ▼
AgentID
  │
  ├── resolve credential
  │
  ├── refresh token
  │
  └── attach credential
        │
        ▼
    MCP Server
```

Credential types:

```text
OAuth tokens
API keys
Service-account credentials
Dynamic tokens
Platform credentials
```

Future implementation:

```text
AgentID
   │
   ▼
Secrets Manager / Vault
   │
   ▼
Credential
```

---

# 13. MCP Registry

The registry stores downstream MCP servers.

Example:

```json
{
  "id": "github",
  "name": "GitHub MCP",
  "endpoint": "http://github-mcp:8000",
  "credential_type": "oauth",
  "enabled": true
}
```

The registry should also maintain tool metadata.

```text
MCP Server
    │
    ├── tools
    ├── resources
    ├── prompts
    └── capabilities
```

---

# 14. Tool Discovery

AgentID should not expose every tool from every MCP server to every agent.

Instead:

```text
Agent
  │
  │ "I need to create a GitHub issue"
  ▼
AgentID Tool Search
  │
  ▼
Relevant tools
  ├── github.create_issue
  ├── github.get_issue
  └── github.search_repository
```

Tool discovery should consider:

```text
query
+
identity
+
permissions
+
available servers
```

Therefore the agent only discovers tools it is actually allowed to use.

---

# 15. MCP Proxy

The proxy is responsible for forwarding authorized requests.

```text
Client
  │
  ▼
Gateway
  │
  ├── authenticate
  ├── authorize
  ├── resolve credential
  ├── audit
  │
  ▼
MCP Router
  │
  ▼
Target MCP Server
```

The proxy should never bypass the authorization layer.

---

# 16. Audit Architecture

Every security-relevant operation produces an audit event.

Example:

```json
{
  "timestamp": "2026-08-24T10:00:00Z",
  "user_id": "user_123",
  "agent_id": "coding-agent",
  "persona": "user",
  "tool": "github.create_issue",
  "server": "github",
  "resource": "company/backend",
  "decision": "allow",
  "execution_identity": "user_123"
}
```

Denied request:

```json
{
  "timestamp": "2026-08-24T10:01:00Z",
  "user_id": "user_123",
  "agent_id": "coding-agent",
  "tool": "kubernetes.delete_namespace",
  "decision": "deny",
  "reason": "missing_permission"
}
```

Autonomous request:

```json
{
  "timestamp": "2026-08-24T10:02:00Z",
  "user_id": null,
  "agent_id": "security-agent",
  "persona": "non-user",
  "tool": "kubernetes.get_logs",
  "decision": "allow",
  "execution_identity": "security-service-account"
}
```

---

# 17. Request Context

Every request should construct an internal request context.

Conceptually:

```python
RequestContext(
    user_id=...,
    agent_id=...,
    persona=...,
    service_account_id=...,
    session_id=...,
    tool=...,
    server=...,
    authorization=...,
)
```

This context should be available to:

```text
Authentication
      ↓
Authorization
      ↓
Credential Manager
      ↓
MCP Proxy
      ↓
Audit
```

This prevents every component from independently trying to reconstruct identity.

---

# 18. Downstream MCP Server

A downstream MCP server should be intentionally simple.

```text
             MCP SERVER
                  │
          ┌───────▼────────┐
          │ Token Verifier  │
          └───────┬────────┘
                  │
          ┌───────▼────────┐
          │ Resource Auth  │
          └───────┬────────┘
                  │
          ┌───────▼────────┐
          │ Tool Execution  │
          └────────────────┘
```

The server verifies:

```text
signature
audience
expiration
issuer
claims
```

The server then performs its own resource-level authorization.

AgentID should provide a shared SDK:

```text
sdk/server/
├── verifier.py
├── claims.py
└── middleware.py
```

This makes onboarding a new MCP server straightforward.

---

# 19. Data Model

Initial database entities:

```text
users
agents
service_accounts
sessions
policies
roles
permissions
servers
tools
credentials
audit_events
delegations
```

Relationships:

```text
User
 │
 ├───────────────┐
 │               │
 ▼               ▼
Agent          Session
 │
 │
 ▼
Delegation
 │
 ▼
Service Account
```

Authorization:

```text
Role
 │
 ▼
Permission
 │
 ▼
Tool
```

Registry:

```text
MCP Server
 │
 ▼
Tools
```

---

# 20. Repository Architecture

```text
agentid/
│
├── gateway/
│   ├── main.py
│   ├── api/
│   ├── middleware/
│   ├── mcp/
│   └── services/
│
├── identity/
│   ├── users.py
│   ├── agents.py
│   ├── service_accounts.py
│   ├── sessions.py
│   └── delegation.py
│
├── authorization/
│   ├── engine.py
│   ├── policies.py
│   ├── rbac.py
│   ├── permissions.py
│   └── decisions.py
│
├── credentials/
│   ├── vault.py
│   ├── oauth.py
│   ├── api_keys.py
│   ├── token_exchange.py
│   ├── token_cache.py
│   └── refresh.py
│
├── registry/
│   ├── servers.py
│   ├── tools.py
│   └── schemas.py
│
├── audit/
│   ├── events.py
│   ├── logger.py
│   └── storage.py
│
├── sdk/
│   └── server/
│       ├── verifier.py
│       ├── claims.py
│       └── middleware.py
│
├── models/
│   ├── user.py
│   ├── agent.py
│   ├── service_account.py
│   ├── session.py
│   ├── policy.py
│   ├── token.py
│   └── audit_event.py
│
├── servers/
│   ├── github/
│   ├── postgres/
│   └── kubernetes/
│
├── database/
│   ├── migrations/
│   └── seed.py
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── security/
│   └── e2e/
│
├── docs/
│   ├── architecture.md
│   ├── authentication.md
│   ├── authorization.md
│   ├── delegation.md
│   ├── security-model.md
│   └── roadmap.md
│
└── deploy/
    ├── docker/
    └── kubernetes/
```

---

# 21. Security Invariants

These are the rules AgentID must never violate.

### Invariant 1

Every request has an authenticated identity.

### Invariant 2

User and non-user personas are distinct.

### Invariant 3

An autonomous agent cannot impersonate a human.

### Invariant 4

Authentication and authorization are separate operations.

### Invariant 5

Gateway authorization occurs before MCP routing.

### Invariant 6

A user cannot use a service account unless explicitly authorized.

### Invariant 7

Downstream credentials are never exposed to the client or agent.

### Invariant 8

Every MCP invocation produces an auditable event.

### Invariant 9

Agents cannot exceed the permissions of their delegating user.

### Invariant 10

Downstream systems retain resource-level authorization.

---

# 22. MVP

The first version should be deliberately small.

## Authentication

```text
[ ] JWT validation
[ ] API keys for machine agents
[ ] Sessions
```

## Identity

```text
[ ] Users
[ ] Agents
[ ] Service accounts
[ ] User → Agent relationships
```

## Authorization

```text
[ ] RBAC
[ ] Tool permissions
[ ] Policy engine
[ ] User → Service Account authorization
```

## MCP

```text
[ ] MCP server registry
[ ] MCP proxy
[ ] Tool discovery
[ ] Tool routing
```

## Security

```text
[ ] Token expiration
[ ] Credential isolation
[ ] User/non-user separation
[ ] Audit logging
```

## Example servers

```text
[ ] GitHub MCP
[ ] PostgreSQL MCP
```

The MVP should be able to demonstrate:

```text
User
 ↓
AgentID
 ↓
GitHub MCP
 ↓
GitHub
```

and:

```text
Unauthorized Agent
 ↓
AgentID
 ↓
403
```

---

# 23. Development Roadmap

## V0 — Foundation

```text
[ ] Repository
[ ] Docker setup
[ ] Gateway skeleton
[ ] Database
[ ] MCP registry
```

## V1 — Identity

```text
[ ] JWT authentication
[ ] Users
[ ] Agents
[ ] Service accounts
[ ] Sessions
```

## V2 — Authorization

```text
[ ] RBAC
[ ] Policy engine
[ ] Tool permissions
[ ] Deny/allow decisions
[ ] User → SA authorization
```

## V3 — MCP Gateway

```text
[ ] MCP proxy
[ ] MCP routing
[ ] Tool discovery
[ ] Tool filtering
```

## V4 — Credentials

```text
[ ] OAuth
[ ] API keys
[ ] Credential manager
[ ] Token cache
[ ] Refresh
```

## V5 — Delegation

```text
[ ] RFC 8693
[ ] User → Agent delegation
[ ] `sub`
[ ] `act`
[ ] Delegation chains
```

## V6 — Observability

```text
[ ] Audit API
[ ] Metrics
[ ] OpenTelemetry
[ ] Authorization dashboards
```

## V7 — Production

```text
[ ] Kubernetes
[ ] Secrets manager
[ ] Redis
[ ] PostgreSQL
[ ] Rate limiting
[ ] Multi-tenancy
[ ] Private MCP tunnels
```

---

# 24. Killer Demo

The final demonstration should show the entire identity chain.

```text
                         AGENTID
                      SECURITY DEMO

USER
Imad
  │
  ▼
AGENT
coding-agent
  │
  ▼
TOOL
github.create_issue
  │
  ▼
POLICY
developer
  │
  ▼
DECISION
✓ ALLOWED
  │
  ▼
GITHUB MCP
```

Then demonstrate a denied request:

```text
USER
Imad
  │
  ▼
AGENT
coding-agent
  │
  ▼
TOOL
kubernetes.delete_namespace
  │
  ▼
POLICY
developer
  │
  ▼
DECISION
✗ DENIED
  │
  ▼
403 Forbidden
  │
  ▼
AUDIT EVENT
```

Finally demonstrate delegation:

```text
USER
Imad
  │
  │ asks agent
  ▼
CODING AGENT
  │
  │ delegated token
  ▼
AGENTID
  │
  │ sub = Imad
  │ act = coding-agent
  ▼
GITHUB MCP
  │
  ▼
AUDIT
User:  Imad
Agent: coding-agent
Tool:  github.create_issue
Result: ALLOWED
```

---

# 25. Long-Term Vision

AgentID should eventually become:

```text
                    ┌─────────────────────────┐
                    │      AI Clients         │
                    └───────────┬─────────────┘
                                │
                                ▼
                    ┌─────────────────────────┐
                    │      AgentID Gateway    │
                    │                         │
                    │ Identity                │
                    │ Authentication          │
                    │ Authorization           │
                    │ Delegation              │
                    │ Credential Management   │
                    │ Tool Discovery          │
                    │ MCP Aggregation         │
                    │ Audit                   │
                    │ Observability           │
                    └───────────┬─────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                 ▼
         GitHub MCP        Database MCP       K8s MCP
              │                 │                 │
              ▼                 ▼                 ▼
          GitHub            Database          Kubernetes
```

The goal is not to create another MCP server.

The goal is to create the **identity and security infrastructure between AI agents and MCP servers**.

That is the core architectural thesis of AgentID.
