# Docker

```bash
# build and start the gateway, PostgreSQL and the three example MCP servers
docker compose -f deploy/docker/docker-compose.yml up --build

# load demo identities, policies and the registry
docker compose -f deploy/docker/docker-compose.yml exec gateway agentid seed

# the gateway is now on http://localhost:8000 (docs at /docs)
curl -s localhost:8000/health
```

The compose file needs `psycopg` for the PostgreSQL URL:

```bash
pip install "psycopg[binary]"
```

or switch `AGENTID_DATABASE_URL` to SQLite for a dependency-free run.

Set real values for `AGENTID_SECRET_KEY` and `AGENTID_CREDENTIAL_ENCRYPTION_KEY`
before using this anywhere but a laptop.
