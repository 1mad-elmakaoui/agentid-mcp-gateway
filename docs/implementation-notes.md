# Implementation notes

Where the code makes a choice the architecture document left open, or departs
from it, the reasoning is recorded here.

---

## 1. Departures from the documented layout

Two, both cosmetic:

**`models/` groups entities by concern, not one file per table.**
The document lists `models/user.py`, `models/agent.py`, `models/service_account.py`.
The code has `models/identity.py` holding `User`, `Agent`, `ServiceAccount` and
the two grant tables. Those five types are meaningless apart — the grant tables
exist only to relate them — and splitting them across five files buys circular
imports and nothing else. Likewise `session.py` holds sessions, API keys and
delegations; `policy.py` holds roles and permissions.

**`tests/` sits at the repository root**, beside `agentid/` rather than inside
it. Tests are not part of the installed package.

Everything else follows the documented tree.

---

## 2. Choices the document left open

### The downstream wire protocol

The gateway speaks JSON-RPC 2.0 `tools/call` and `tools/list` to downstream
servers — the MCP method names — over HTTP POST to `<endpoint>/mcp`. This keeps
a real MCP server compatible with the proxy once fronted by the SDK middleware.

### Two token audiences

The document describes gateway-issued credentials without fixing their shape.
The implementation mints a **separate token per downstream call**, with audience
`agentid-mcp:<server>` and a 120-second lifetime, distinct from the
`agentid-gateway` audience clients present. This makes two attacks structurally
impossible rather than merely disallowed: a client cannot replay its own token
at an MCP server, and a token minted for one server will not verify at another.

### Grantee of a service account

Architecture §8 describes `User → Service Account`. When an agent is in the
chain, the code checks the grant against the **human**, not the agent. Checking
the agent instead would let a user reach a service account they were never
granted, simply by delegating to an agent that holds the grant — which is
Threat 2 wearing a different hat. For autonomous calls, where there is no human,
the agent is the grantee.

### A grant does not widen an identity

Beyond the grant check, the service account must itself hold the tool's
permission. Borrowing an identity gets you that identity's authority and no
more.

### Service accounts as direct callers

The document treats service accounts purely as execution identities. The code
also allows a service account holding its own API key to call the gateway
directly — a cron job with no agent in front of it. It is then its own
principal, needs no grant (there is nothing to borrow), and is still bound by
its own roles.

### Deny beats allow, always

The policy example shows `allow` and `deny` lists without stating precedence.
The engine resolves deny first, regardless of specificity: `deny: kubernetes.**`
beats `allow: kubernetes.delete_namespace`. The surprising direction is the safe
one.

### Permission patterns

`*` matches one dotted segment, `**` matches the remainder. Two characters of
syntax, so `github.*` cannot silently swallow `github.admin.delete_org`.

---

## 3. Deliberate non-goals for this version

* **Symmetric signing (HS256).** Downstream servers share the gateway's signing
  secret. Asymmetric keys plus a JWKS endpoint is the right answer for a
  multi-team deployment; it changes only `TokenService` and `TokenVerifier`.
* **`create_all` instead of migrations.** `database/migrations/` documents the
  intended Alembic setup but the schema is currently created from the models.
* **In-process rate limiting and credential cache.** Neither coordinates across
  replicas. Both sit behind interfaces a Redis backend can implement.
* **Synchronous DB sessions inside async endpoints.** Correct but blocking. At
  MVP scale it is not the bottleneck; under load it is the first thing to change.

---

## 4. Things worth knowing when reading the code

**`RequestContext` is built once.** Authentication constructs it; authorization,
the credential manager, the proxy and the audit logger all read it. No component
re-derives identity, which is what stops two components disagreeing about who
the caller is.

**`ctx.service_account_id` is set *after* authorization**, by the service, from
the decision. Before that point the field is empty for user-driven calls — the
execution identity is an *output* of authorization, not an input to it.

**Discovery and invocation share one engine.** `discover()` runs the full
catalog through `authorize_tool`. Slower than a permission-set intersection, and
correct by construction: there is no second implementation to drift.

**Audit writes happen on every path.** Allowed, denied, unroutable and
downstream-error all produce exactly one `mcp.call` event before the response
leaves. `test_invariant_8_every_invocation_is_audited` counts them.

**The `EnumType` column decorator exists for a reason.** A plain `String` column
holding a `str`-valued enum round-trips to `str`, so `event.persona.value`
raises after a fresh query but not before. The decorator converts back on read.
