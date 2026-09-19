# Delegation

> Who authorized this operation, and who actually performed it?

Without delegation an audit trail can only answer one of those questions. This
is the loss described as Threat 6 in the [security model](security-model.md).

---

## 1. The chain

```text
USER
Imad
  │
  │ asks the agent to act
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
User:   Imad
Agent:  coding-agent
Tool:   github.create_issue
Result: ALLOWED
```

---

## 2. Obtaining a delegated token

```http
POST /auth/token
Content-Type: application/json

{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<the user's access token>",
  "actor": "coding-agent",
  "scope": "mcp:tools"
}
```

```json
{
  "access_token": "eyJhbGciOi...",
  "token_type": "Bearer",
  "issued_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "expires_in": 900,
  "delegation_id": "dlg_6b1f..."
}
```

The shape follows RFC 8693 §2. `actor` names the agent that will act — by id or
by name.

---

## 3. What the gateway checks

```text
subject token verifies, is not a downstream token
        │
        ▼
session still active
        │
        ▼
subject is a USER with the user persona          ← invariant 3
        │
        ▼
agent exists, is enabled, is NOT autonomous      ← invariant 3
        │
        ▼
user has an explicit, unrevoked grant for it     ← invariant 9 precondition
        │
        ▼
issue sub = user, act.sub = agent
record a Delegation row
```

Four things are deliberately *not* sufficient on their own:

* owning an agent — ownership is a management relationship, not authorization;
* the agent holding broad permissions — the intersection still applies;
* a valid user token — the grant is checked separately;
* a valid agent token — a machine cannot exchange its way into a user persona.

---

## 4. The token

```json
{
  "sub": "user_123",
  "act": { "sub": "coding-agent", "sub_type": "agent" },
  "aud": "agentid-gateway",
  "persona": "user",
  "typ": "delegated",
  "scope": "mcp:tools",
  "sid": "sess_...",
  "did": "dlg_...",
  "exp": "<15 minutes out>"
}
```

* `sub` — who authorized the operation
* `act.sub` — who performs it
* `did` — the delegation record, so revocation is immediate

---

## 5. Through to the downstream server

The gateway does not forward the delegated token. It mints a fresh,
single-audience credential for the one server being called, and that credential
carries the chain forward:

```json
{
  "aud": "agentid-mcp:github",
  "sub": "user_123",
  "act": { "sub": "coding-agent" },
  "on_behalf_of": "user_123",
  "typ": "downstream",
  "exp": "<120 seconds out>"
}
```

The server's SDK exposes this as a single readable chain:

```python
claims.human_user      # "user_123"
claims.agent           # "coding-agent"
claims.identity_chain()  # "user_123 -> coding-agent"
```

When a service account is in play, `sub` becomes the service account and the
chain reads `user_123 -> coding-agent -> sa_prod_deployer`.

---

## 6. Permissions still bind

A delegated token does not widen anything:

```text
Effective = User ∩ Agent
```

The agent is bounded above by its delegating user, and the user is bounded by
the agent they chose. Both denies apply. See
[authorization.md](authorization.md#4-effective-permissions).

---

## 7. Revocation

| Action | Effect on delegated tokens |
| --- | --- |
| `POST /auth/logout` | every token on that session stops working |
| revoke the delegation | that token stops working |
| `DELETE /identity/users/{id}/agents/{agent}` | no *new* delegations; existing tokens die with their delegation or session |
| disable the agent | every path through it stops working |

Each is checked per request, so none of them wait for token expiry.

---

## 8. Delegation chains

The model stores one acting agent per token (`act.sub`), matching RFC 8693's
delegation claim. Longer chains — agent handing off to sub-agent — would nest
`act` and are left for a later version; the audit schema already carries the
distinct `agent_id` and `execution_identity` columns such a chain would need.
