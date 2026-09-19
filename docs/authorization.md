# Authorization

> Are you allowed to do this?

Authorization runs after authentication and **before** any MCP request is
routed (invariants 4 and 5). The proxy is only ever handed a decision that
already allows.

---

## 1. Two layers

```text
AgentID
  │
  └── "may this identity use this tool?"        gateway authorization
          │
          ▼
       GitHub MCP
          │
          └── "may this identity touch repo X?" downstream authorization
```

The gateway does not attempt to reproduce every downstream permission system.
It answers the tool question; the MCP server keeps the resource question
(invariant 10).

---

## 2. Permissions

A permission is a dotted name. Patterns may use `*` for one segment or `**` as
a trailing catch-all.

```text
github.create_issue   exactly that tool
github.*              any single-segment github tool
github.**             github and everything below it
*                     everything
```

By default a tool's required permission is its own qualified name, so
`github.create_issue` is guarded by `github.create_issue`. A tool may override
this with `required_permission` when several tools should share one permission.

---

## 3. Roles and policy documents

A role carries **allow** and **deny** entries. Deny always wins, regardless of
specificity.

```yaml
roles:
  - role: developer
    description: Day-to-day engineering access
    allow:
      - github.read
      - github.create_issue
      - database.read
    deny:
      - kubernetes.delete_namespace
      - database.drop
      - production.deploy
```

Bundles are declarative: applying one replaces the listed roles' entries, so the
file stays the source of truth. Apply with either:

```bash
agentid policy policies/default.yaml
# or
PUT /policy/bundle
```

The shipped bundle is [`policies/default.yaml`](../policies/default.yaml).

---

## 4. Effective permissions

```text
Effective Permissions
    =
User Permissions
    ∩
Agent Permissions
```

The intersection cuts both ways. An agent never gains a permission its
delegating user lacks, and a user never reaches a tool through an agent that
does not hold it either.

```text
user:   github.read, github.create_issue, database.read
agent:  github.read, github.create_issue, kubernetes.read
        ────────────────────────────────────────────────
result: github.read, github.create_issue
```

Patterns cannot be intersected as sets, so the engine evaluates each side
independently and requires both to permit. A deny on **either** side rejects.

---

## 5. Evaluation order

Most restrictive first, so the earliest possible rejection wins:

```text
1  authenticated identity present?        → unauthenticated
2  persona coherent?                      → persona_violation
3  required scope present?                → missing_scope
4  tool and server exist and enabled?     → unknown_tool / *_disabled
5  explicit deny on any identity?         → explicit_deny
6  user holds the permission?             → missing_permission
7  agent holds the permission?            → exceeds_user_permissions
8  execution identity resolvable?         → service_account_*
```

---

## 6. Execution identity

Step 8 decides what the downstream call actually runs as.

```text
tool.requires_service_account == false
    └── execution identity = user, else agent

tool.requires_service_account == true
    ├── which service account? (explicit request, else the tool default)
    ├── is there an unrevoked grant for the caller?        ← invariant 6
    └── does the service account itself hold the permission?
```

The grantee is the **human** when one is in the chain, and the agent otherwise.
An agent cannot escalate by holding a grant its delegating user does not have.

A grant lets you borrow an identity; it does not widen what that identity may
do. A service account with no matching role is refused even to a caller who
holds the grant.

---

## 7. Decisions

Every check returns a structured decision, which is what the audit trail
records:

```json
{
  "decision": "deny",
  "reason": "missing_permission",
  "policy": "developer",
  "permission": "kubernetes.delete_namespace",
  "tool": "kubernetes.delete_namespace",
  "server": "kubernetes"
}
```

| Reason | Meaning |
| --- | --- |
| `allowed` | the chain permits the tool |
| `unauthenticated` | no identity, or an identity that no longer resolves |
| `missing_permission` | the user lacks the permission |
| `agent_not_permitted` | a non-delegated agent lacks it |
| `exceeds_user_permissions` | the agent lacks what its user holds |
| `explicit_deny` | a deny entry matched |
| `service_account_not_authorized` | no grant for that service account |
| `service_account_not_permitted` | the service account itself lacks it |
| `service_account_required` | the tool needs one and none was resolved |
| `persona_violation` | a machine identity wearing a human's, or the reverse |
| `identity_disabled` | user, agent or service account is disabled |
| `missing_scope` | the token lacks `mcp:tools` |
| `tool_disabled` / `server_disabled` | the target is turned off |

---

## 8. Discovery uses the same engine

`/mcp/tools` and `/mcp/tools/search` evaluate the *whole* catalog through the
engine and return only what the caller could actually invoke. A tool the caller
may not use is never named — the response reports a `filtered_out` count and
nothing more. One engine, one decision table, no second implementation to drift.

---

## 9. Administration

Administrative routes require the `agentid.admin` permission, evaluated through
the same intersection rule. A delegated caller needs the permission on **both**
the user and the agent, so handing a task to an agent never silently hands over
administrative access.
