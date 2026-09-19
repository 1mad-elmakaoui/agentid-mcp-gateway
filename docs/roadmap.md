# Roadmap

Status of the phases described in the architecture document.

| | Phase | Status |
| --- | --- | --- |
| V0 | Foundation | **done** |
| V1 | Identity | **done** |
| V2 | Authorization | **done** |
| V3 | MCP Gateway | **done** |
| V4 | Credentials | partial |
| V5 | Delegation | partial |
| V6 | Observability | partial |
| V7 | Production | planned |

---

## V0 — Foundation ✅

- [x] Repository layout
- [x] Docker setup (`deploy/docker`)
- [x] Gateway skeleton (`agentid/gateway`)
- [x] Database (SQLAlchemy models, SQLite by default, PostgreSQL supported)
- [x] MCP registry

## V1 — Identity ✅

- [x] JWT authentication
- [x] Users, agents, service accounts
- [x] Sessions with immediate revocation
- [x] API keys for machine callers
- [x] User → agent grants

## V2 — Authorization ✅

- [x] RBAC with allow/deny patterns
- [x] Policy engine returning structured decisions
- [x] Tool permissions
- [x] `user ∩ agent` effective permissions
- [x] User → service-account authorization

## V3 — MCP Gateway ✅

- [x] MCP proxy (JSON-RPC `tools/call`, `tools/list`)
- [x] Routing
- [x] Tool discovery with intent ranking
- [x] Permission filtering — a caller never sees a tool it may not invoke

## V4 — Credentials ◐

- [x] Credential manager owned by the gateway
- [x] Encrypted vault (Fernet) with a pluggable backend seam
- [x] API-key and OAuth credential types
- [x] TTL cache
- [x] Refresh provider registry
- [ ] Real OAuth authorization-code flow against downstream providers
- [ ] External secrets manager backend (Vault, AWS Secrets Manager)

## V5 — Delegation ◐

- [x] RFC 8693 shaped token exchange
- [x] `sub` / `act` preserved end to end
- [x] Delegation records with immediate revocation
- [ ] Nested delegation chains (agent → sub-agent)
- [ ] Token exchange against an external identity provider (BYOT)

## V6 — Observability ◐

- [x] Append-only audit store with redaction
- [x] Audit query API
- [x] Request ids propagated end to end and echoed on every response
- [ ] Prometheus metrics
- [ ] OpenTelemetry traces spanning gateway and downstream servers
- [ ] Authorization dashboards

## V7 — Production ☐

- [x] Kubernetes manifests (`deploy/kubernetes`)
- [x] Fixed-window rate limiting (in-process)
- [ ] Redis-backed rate limiting and credential cache
- [ ] Asymmetric token signing with a JWKS endpoint
- [ ] Multi-tenancy
- [ ] Private MCP tunnels
- [ ] Alembic migrations (the schema is currently created from the models)

---

## Known limitations

These are deliberate scope choices, not oversights:

* **Token signing is symmetric (HS256).** Downstream servers therefore share the
  signing secret with the gateway. Asymmetric signing plus JWKS is the fix and
  is the first thing to do before a multi-team deployment.
* **The schema is created from the models.** Fine for development and the demo;
  a real deployment wants migrations.
* **Rate limiting and the credential cache are in-process.** They do not
  coordinate across replicas.
* **The database session is synchronous** inside async endpoints. At the MVP's
  scale this is not a bottleneck, but it is the obvious thing to revisit under
  load.
* **The example MCP servers are in-memory fakes.** They exist to exercise the
  identity path end to end, not to be real integrations.
