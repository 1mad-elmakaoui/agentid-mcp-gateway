# AgentID Security Model

## 1. Purpose

AgentID is designed around a zero-trust security model for AI agents interacting with MCP servers.

The gateway assumes that:

- AI agents cannot automatically be trusted.
- Authentication does not imply authorization.
- A user's permissions must not automatically become an agent's permissions.
- Autonomous agents must remain distinct from human users.
- Downstream credentials must remain hidden from clients and agents.
- Every MCP operation must be auditable.

The objective is to establish a clear security boundary between AI clients, agents, the AgentID gateway, and downstream MCP servers.

---

## 2. Security Boundaries

AgentID defines four primary security boundaries:

```text
AI Client
    │
    │ Untrusted request
    ▼
AgentID Gateway
    │
    │ Authorized request
    ▼
MCP Server
    │
    │ Resource authorization
    ▼
Protected Resource
```

The gateway is the primary control point for identity and tool-level authorization.

The downstream MCP server remains responsible for resource-level authorization.

---

## 3. Identity Model

AgentID distinguishes between three identities:

```text
User
  │
  └── operates
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

A human identity authenticated through an appropriate authentication mechanism.

### Agent

An AI agent or application acting on behalf of a user or operating autonomously.

### Service Account

A machine identity used when execution requires non-human credentials.

These identities must never be implicitly interchangeable.

---

## 4. User vs Non-User Personas

AgentID separates callers into two primary personas:

```text
USER
Human-driven execution
        │
        └── User identity


NON-USER
Autonomous execution
        │
        └── Machine identity
```

This distinction is a security boundary.

An autonomous agent must never obtain a human user's identity simply because it requires access to a resource.

For example, this is invalid:

```text
Autonomous Agent
      │
      ▼
"I need access"
      │
      ▼
Impersonate User
      │
      ▼
User credentials
```

Instead:

```text
Autonomous Agent
      │
      ▼
Agent Identity
      │
      ▼
Authorized Service Account
```

---

## 5. Authentication vs Authorization

Authentication and authorization are independent operations.

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

A successfully authenticated request must not automatically be considered authorized.

Example:

```text
User = developer
Tool = kubernetes.delete_namespace

Authentication:
✓ Valid identity

Authorization:
✗ Missing permission

Final result:
403 Forbidden
```

---

## 6. Agent Permission Boundaries

An agent must never exceed the permissions of the user who delegated the action.

Conceptually:

```text
Effective Permissions
=
User Permissions
∩
Agent Permissions
```

Example:

```text
User permissions:

github.read
github.create_issue
database.read
```

Agent permissions:

```text
github.read
github.create_issue
kubernetes.read
```

Effective permissions:

```text
github.read
github.create_issue
```

The agent does not inherit `kubernetes.read` simply because the agent itself has that capability.

---

## 7. User → Agent Delegation

For user-driven execution:

```text
User
  │
  │ delegates action
  ▼
Agent
  │
  │ MCP request
  ▼
AgentID
  │
  ▼
MCP Server
```

AgentID must preserve both identities.

Conceptually:

```json
{
  "sub": "user_123",
  "act": {
    "sub": "coding-agent"
  }
}
```

This allows the system to answer two different questions:

```text
Who authorized the operation?
        ↓
user_123

Who actually performed the operation?
        ↓
coding-agent
```

---

## 8. User → Service Account

Service-account credentials are sensitive and must remain controlled by AgentID.

The correct flow is:

```text
User
 │
 ▼
AgentID
 │
 ├── Verify user
 │
 ├── Verify service-account permission
 │
 ├── Resolve credential
 │
 └── Attach credential
 │
 ▼
MCP Server
```

The client must never provide the downstream service-account credential directly.

If the user is not authorized:

```text
User
  │
  ▼
AgentID
  │
  ▼
Service Account Authorization
  │
  ▼
DENIED
  │
  ▼
403 Forbidden
```

---

## 9. Credential Isolation

Downstream credentials belong to AgentID.

The following flow is prohibited:

```text
MCP Client
    │
    ▼
Agent
    │
    ▼
Service Account Secret
```

The correct model is:

```text
MCP Client
    │
    ▼
AgentID
    │
    ├── Credential Manager
    │
    └── Secret Storage
           │
           ▼
       Credential
           │
           ▼
       MCP Server
```

Agents should receive authorization to perform an operation, not the underlying long-lived secret required to perform it.

---

## 10. Gateway Authorization

The gateway evaluates whether an identity can access a particular MCP server or tool.

Example:

```text
Identity:
developer

Tool:
github.create_issue

Decision:
ALLOW
```

Another request:

```text
Identity:
developer

Tool:
kubernetes.delete_namespace

Decision:
DENY
```

The gateway must perform this authorization before forwarding the MCP request.

---

## 11. Downstream Authorization

Gateway authorization and downstream authorization serve different purposes.

### Gateway

```text
Can this identity use this tool?
```

### Downstream system

```text
Can this identity access this specific resource?
```

Example:

```text
AgentID
  │
  └── "User may use GitHub"
          │
          ▼
       GitHub
          │
          └── "User may modify repository X"
```

AgentID should not attempt to duplicate every permission system implemented by downstream platforms.

---

## 12. Threat Scenarios

### Threat 1 — Autonomous Agent Impersonation

An autonomous agent attempts to operate as a human user.

```text
Security Agent
      │
      ▼
Impersonate user_123
      │
      ▼
Access protected resources
```

**Mitigation:**

Non-user identities must remain separate from user identities.

---

### Threat 2 — Privilege Escalation Through Agent

A user has limited permissions, while an agent has additional capabilities.

```text
User:
github.read

Agent:
github.read
kubernetes.delete_namespace
```

The agent attempts to use:

```text
kubernetes.delete_namespace
```

**Mitigation:**

Effective permissions are constrained by the intersection of user and agent permissions.

---

### Threat 3 — Unauthorized Service Account Usage

A user attempts to execute using a privileged service account.

```text
User
 ↓
Agent
 ↓
production-deployer
```

The user has not been granted access to that service account.

**Mitigation:**

AgentID explicitly checks:

```text
User → Service Account
```

authorization before resolving the credential.

---

### Threat 4 — Credential Exposure

An agent attempts to obtain the API key used by a downstream MCP server.

**Mitigation:**

Credentials are resolved inside AgentID and attached to downstream requests without exposing them to the client or agent.

---

### Threat 5 — Unauthorized Tool Invocation

An authenticated agent invokes a restricted tool.

```text
Agent
 ↓
AgentID
 ↓
restricted_tool
```

**Mitigation:**

Authentication succeeds, but authorization fails.

```text
401/403
+
Audit Event
```

---

### Threat 6 — Audit Ambiguity

A user delegates an action to an AI agent, but the system records only the user's identity.

```text
User: user_123
```

This loses information about the actual actor.

**Mitigation:**

Delegated identity preserves:

```text
sub = user
act = agent
```

allowing the audit system to record both identities.

---

## 13. Security Invariants

The following properties must always hold:

1. Every request has an authenticated identity.
2. Human and autonomous personas remain distinct.
3. Autonomous agents cannot impersonate humans.
4. Authentication and authorization remain separate.
5. Authorization occurs before MCP routing.
6. Service accounts require explicit authorization.
7. Downstream credentials are never exposed to agents.
8. Every MCP invocation produces an audit event.
9. Agents cannot exceed the permissions of their delegating users.
10. Downstream systems retain resource-level authorization.

These invariants should be treated as security requirements rather than optional features.

---

## 14. Security Testing Strategy

Security tests should verify both allowed and denied behavior.

### Identity Tests

```text
✓ Valid user accepted
✓ Valid agent accepted
✓ Valid service account accepted
✗ Invalid identity rejected
✗ Autonomous agent cannot become user
```

### Authorization Tests

```text
✓ Allowed tool executes
✗ Unauthorized tool rejected
✗ Unauthorized service account rejected
✗ Agent cannot exceed user permissions
```

### Credential Tests

```text
✓ Gateway resolves credential
✓ Credential attached to downstream request
✗ Credential returned to agent
✗ Credential exposed in audit logs
```

### Delegation Tests

```text
✓ User → Agent delegation preserved
✓ User identity preserved
✓ Agent identity preserved
✗ Invalid delegation rejected
```

### Audit Tests

```text
✓ Allowed requests logged
✓ Denied requests logged
✓ User identity recorded
✓ Agent identity recorded
✓ Execution identity recorded
```

---

## 15. Security Philosophy

AgentID follows a simple principle:

> **Authenticate the actor, authorize the action, protect the credential, and record the decision.**

The gateway should never assume that an AI agent is trustworthy merely because it is operating on behalf of an authenticated user.

Every MCP operation should pass through the same security lifecycle:

```text
Authenticate
     ↓
Resolve Identity
     ↓
Determine Persona
     ↓
Authorize
     ↓
Resolve Credential
     ↓
Route MCP Request
     ↓
Audit
```

This lifecycle forms the security foundation of AgentID.
