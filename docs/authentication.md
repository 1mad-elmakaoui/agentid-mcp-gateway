# Authentication

> Who is making this request?

Authentication answers one question and nothing else. Whether the caller may do
what they are asking is a separate operation, documented in
[authorization.md](authorization.md). The separation is security invariant 4.

---

## 1. Credential shapes

The gateway accepts two kinds of credential.

```text
Authorization: Bearer <jwt>        gateway token (user, agent, or delegated)
Authorization: Bearer aid_sk_...   API key (machine callers)
X-API-Key: aid_sk_...              API key (equivalent form)
```

Everything else is rejected with `401`.

| Caller | Credential | Persona |
| --- | --- | --- |
| Human, interactive | JWT from `POST /auth/login` | `user` |
| Agent acting for a human | delegated JWT from `POST /auth/token` | `user` |
| Autonomous agent | API key or agent JWT | `non-user` |
| Service account job | API key or service-account JWT | `non-user` |

An API key can never yield a user persona, whatever its owner. That is how
invariant 3 — an autonomous agent cannot impersonate a human — is enforced at
the door rather than deeper in the stack.

---

## 2. Token families

Two token families exist, and they are deliberately not interchangeable.

```text
                 ┌──────────────────────────────┐
                 │        CLIENT TOKEN          │
                 │  aud = agentid-gateway       │
                 │  presented BY a client       │
                 │  TO the gateway              │
                 └──────────────┬───────────────┘
                                │
                        gateway mints
                                │
                                ▼
                 ┌──────────────────────────────┐
                 │      DOWNSTREAM TOKEN        │
                 │  aud = agentid-mcp:<server>  │
                 │  minted BY the gateway       │
                 │  FOR one MCP server          │
                 └──────────────────────────────┘
```

Because the audiences differ, a client token replayed directly at an MCP server
fails verification, and a downstream token presented back to the gateway is
rejected with `wrong_token_type`. A downstream token is also scoped to a single
server: the one minted for `github` will not verify at `kubernetes`.

### Client token claims

```json
{
  "iss": "agentid",
  "aud": "agentid-gateway",
  "sub": "user_123",
  "sub_type": "user",
  "act": { "sub": "coding-agent", "sub_type": "agent" },
  "persona": "user",
  "typ": "delegated",
  "scope": "mcp:tools",
  "sid": "sess_...",
  "did": "dlg_...",
  "iat": 1755000000,
  "exp": 1755000900
}
```

`act` is present only on delegated tokens. `did` binds the token to a delegation
record, so revoking the delegation invalidates the token immediately rather than
at its own expiry.

### Downstream token claims

```json
{
  "iss": "agentid",
  "aud": "agentid-mcp:github",
  "sub": "sa_prod_deployer",
  "sub_type": "service_account",
  "act": { "sub": "coding-agent" },
  "on_behalf_of": "user_123",
  "execution_identity": "sa_prod_deployer",
  "persona": "user",
  "typ": "downstream",
  "tool": "github.create_issue",
  "rid": "req_...",
  "exp": "<120 seconds out>"
}
```

`sub` is the *execution identity*: the service account when one is in play,
otherwise the user, otherwise the agent. `on_behalf_of` and `act` keep the rest
of the chain visible so the downstream server's own audit trail is complete.

---

## 3. Flows

### Password login

```text
Client                         AgentID
  │                              │
  │  POST /auth/login            │
  │  { email, password }         │
  │─────────────────────────────►│
  │                              │ verify (scrypt)
  │                              │ create session
  │                              │ issue access token
  │  { access_token, session_id }│
  │◄─────────────────────────────│
```

An unknown email and a wrong password return the identical response, so the
endpoint cannot be used to enumerate accounts.

### Delegation (RFC 8693 token exchange)

```text
POST /auth/token
{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "<user access token>",
  "actor": "coding-agent"
}
```

The gateway checks, in order:

1. the subject token verifies, is not a downstream token, and its session is live;
2. the subject is a **user** with the user persona — a machine token cannot be
   exchanged for a user-persona token;
3. the named agent exists, is enabled, and is **not autonomous**;
4. the user has an explicit, unrevoked grant for that agent.

Only then is a delegated token issued and a `Delegation` row written.

### Machine authentication

```text
Agent                          AgentID
  │  X-API-Key: aid_sk_<id>.<secret>
  │─────────────────────────────►│
  │                              │ look up by key id
  │                              │ verify secret (scrypt, constant time)
  │                              │ persona := non-user, always
```

The key is `aid_sk_<key_id>.<secret>`. Only the key id is stored in clear; the
secret is stored hashed and returned exactly once, at creation.

---

## 4. Session and delegation revocation

```text
revoke session  ──►  every token carrying that sid stops working
revoke delegation ►  every token carrying that did stops working
revoke api key   ──►  the key stops working
disable user/agent ► every path through that identity stops working
```

Revocation is checked on every request rather than cached, so it takes effect
immediately instead of at token expiry.

---

## 5. Defaults

| Token | Default lifetime |
| --- | --- |
| Access token | 1 hour |
| Delegated token | 15 minutes |
| Downstream token | 120 seconds |
| Session | 24 hours |

All are configurable through `AGENTID_*` environment variables — see
[configuration](../README.md#configuration).

---

## 6. Roadmap

The MVP validates gateway-signed JWTs (HS256) and API keys. The design leaves
room for, in order: asymmetric signing with a JWKS endpoint, OAuth 2.0
Authorization Code + PKCE for interactive clients, the device code flow for
CLIs, and token introspection against an external identity provider. None of
these change the token families above — only how the *first* token is obtained.
