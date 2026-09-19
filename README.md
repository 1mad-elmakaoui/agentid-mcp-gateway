# AgentID

> Zero-trust identity and security gateway for MCP agents.

AgentID sits between AI agents and MCP servers and owns the parts every MCP
server would otherwise reimplement: **who is calling, what they may do, which
credential the call runs under, and what was recorded about it.**

```text
AI clients ──► AgentID gateway ──► MCP servers ──► protected resources
                    │
        authenticate · authorize · resolve credential · route · audit
```

The goal is not another MCP server. It is the identity and security
infrastructure *between* agents and MCP servers.

---

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .

# the whole story in one command — no containers, no network
python scripts/demo.py
```

The demo runs the gateway and three MCP servers in-process and walks four
scenarios: an allowed delegated call, a denied one, a refused service-account
escalation, and an autonomous agent with no human in the chain — then prints the
audit trail.

To run it as a service instead:

```bash
agentid init            # create the schema
agentid seed            # demo identities, policies, registry
agentid serve gateway   # http://localhost:8000  (docs at /docs)
```

---

## What it does

| | |
| --- | --- |
| **Authentication** | JWT and API keys, sessions, immediate revocation |
| **Identity** | users, agents and service accounts as three distinct types |
| **Authorization** | RBAC with allow/deny patterns and structured decisions |
| **Delegation** | RFC 8693 token exchange preserving `sub` **and** `act.sub` |
| **Credentials** | sealed vault; secrets never leave the gateway |
| **Registry** | MCP server catalog with permission-filtered tool discovery |
| **Proxy** | JSON-RPC routing that cannot bypass authorization |
| **Audit** | one append-only event per operation, carrying the whole chain |

---

## The three identity types

```text
User ──authorizes──► Agent ──may execute through──► Service Account
```

They are never implicitly interchangeable. An API key cannot produce a human
identity; an autonomous agent cannot be delegated to; a service account cannot
be borrowed without an explicit grant.

### Effective permissions

```text
Effective = User Permissions ∩ Agent Permissions
```

The intersection cuts both ways. An agent never gains a permission its user
lacks, and a user never reaches a tool through an agent that lacks it. A deny on
either side rejects.

---

## A call, end to end

```bash
# 1. the human logs in
TOKEN=$(curl -s localhost:8000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"imad@example.com","password":"demo-password"}' | jq -r .access_token)

# 2. the human delegates to an agent — sub = user, act.sub = agent
AGENT=$(curl -s localhost:8000/auth/token \
  -H 'content-type: application/json' \
  -d "{\"grant_type\":\"urn:ietf:params:oauth:grant-type:token-exchange\",
       \"subject_token\":\"$TOKEN\",\"actor\":\"coding-agent\"}" | jq -r .access_token)

# 3. the agent discovers only what it may actually invoke
curl -s localhost:8000/mcp/tools/search -H "authorization: Bearer $AGENT" \
  -H 'content-type: application/json' \
  -d '{"query":"create a github issue"}'

# 4. and calls it
curl -s localhost:8000/mcp/call -H "authorization: Bearer $AGENT" \
  -H 'content-type: application/json' \
  -d '{"tool":"github.create_issue",
       "arguments":{"repo":"company/backend","title":"Flaky test in CI"}}'

# 5. the audit trail names both identities
curl -s "localhost:8000/audit/events?tool=github.create_issue" \
  -H "authorization: Bearer $ADMIN_TOKEN"
```

A tool the caller may not use is not merely refused at step 4 — it is absent
from step 3.

---

## Repository layout

```text
agentid/
├── gateway/        FastAPI app, routers, middleware, MCP proxy and router
├── identity/       users, agents, service accounts, sessions, delegation, tokens
├── authorization/  RBAC, policies, permission matching, the decision engine
├── credentials/    vault, resolution, refresh, token exchange, cache
├── registry/       MCP server catalog and tool discovery
├── audit/          event construction, redaction, sinks, queries
├── sdk/server/     verifier, claims and middleware for downstream MCP servers
├── servers/        example GitHub, PostgreSQL and Kubernetes MCP servers
├── models/         SQLAlchemy entities
└── database/       engine, seed data, migration notes

docs/       architecture, authentication, authorization, delegation,
            security model, implementation notes, roadmap
policies/   the default policy bundle
scripts/    the demo
deploy/     Docker and Kubernetes
tests/      unit · integration · security · e2e
```

---

## Writing an MCP server for AgentID

A downstream server stays small: verify the gateway credential, then apply your
own resource rules.

```python
from fastapi import Depends, FastAPI
from agentid.sdk.server import GatewayClaims, TokenVerifier, gateway_identity, install

app = FastAPI()
install(app, TokenVerifier(secret=SECRET, audience="agentid-mcp:github"))

@app.post("/tools/create_issue")
def create_issue(body: dict, identity: GatewayClaims = Depends(gateway_identity)):
    # The gateway said "may use this tool". You say "may touch this resource".
    if not may_write(identity, body["repo"]):
        raise ResourceDenied(body["repo"])
    ...
```

`identity` carries the whole chain:

```python
identity.human_user        # who authorized it (None when autonomous)
identity.agent             # who performed it
identity.service_account   # what it executed as
identity.identity_chain()  # "user_123 -> coding-agent -> sa_prod"
```

The credential is minted per call, for your audience only, and expires in two
minutes. A token issued for another server will not verify at yours.

---

## Tests

```bash
pytest                  # everything
pytest -m security      # the ten security invariants
pytest -m e2e           # full flows through to the MCP servers
```

`tests/security/test_invariants.py` has one test per invariant, named for the
invariant it pins down. If a change breaks one, the failure says which.

---

## Configuration

Everything is read from `AGENTID_*` environment variables (or a `.env` file).

| Variable | Default | Notes |
| --- | --- | --- |
| `AGENTID_DATABASE_URL` | `sqlite:///./agentid.db` | PostgreSQL supported |
| `AGENTID_SECRET_KEY` | dev placeholder | **must** be set in production |
| `AGENTID_CREDENTIAL_ENCRYPTION_KEY` | falls back to the secret key | vault key |
| `AGENTID_ACCESS_TOKEN_TTL_SECONDS` | `3600` | |
| `AGENTID_DELEGATED_TOKEN_TTL_SECONDS` | `900` | |
| `AGENTID_DOWNSTREAM_TOKEN_TTL_SECONDS` | `120` | per-call credential |
| `AGENTID_SESSION_TTL_SECONDS` | `86400` | |
| `AGENTID_RATE_LIMIT_ENABLED` | `true` | in-process, fixed window |
| `AGENTID_POLICY_FILE` | unset | policy bundle to apply |
| `AGENTID_AUDIT_STDOUT` | `true` | JSON lines alongside the database |

---

## Documentation

| Document | What it covers |
| --- | --- |
| [architecture.md](docs/architecture.md) | the full design |
| [security-model.md](docs/security-model.md) | boundaries, threats, invariants |
| [authentication.md](docs/authentication.md) | credentials, token families, flows |
| [authorization.md](docs/authorization.md) | permissions, roles, evaluation order |
| [delegation.md](docs/delegation.md) | `sub` / `act` end to end |
| [implementation-notes.md](docs/implementation-notes.md) | choices and departures |
| [roadmap.md](docs/roadmap.md) | status and known limitations |

---

## Status

The MVP is complete: V0–V3 in full, V4–V6 in part. Before production, read the
[known limitations](docs/roadmap.md#known-limitations) — in particular that
tokens are signed symmetrically in this version, so the gateway and downstream
servers share a secret.

> Authenticate the actor, authorize the action, protect the credential, and
> record the decision.
