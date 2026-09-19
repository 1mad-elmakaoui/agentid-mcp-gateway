# Kubernetes

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
kubectl apply -f deploy/kubernetes/secret.yaml        # replace the values first
kubectl apply -f deploy/kubernetes/gateway.yaml
kubectl apply -f deploy/kubernetes/mcp-servers.yaml
kubectl apply -f deploy/kubernetes/networkpolicy.yaml
```

Before running this anywhere real:

* replace `secret.yaml` with a real secrets source — External Secrets, Vault
  Agent or SOPS;
* point `AGENTID_DATABASE_URL` at a managed PostgreSQL;
* build and push the image, and set the real reference in place of
  `ghcr.io/example/agentid:0.1.0`;
* read the token-signing note in [../../docs/roadmap.md](../../docs/roadmap.md) —
  this version signs symmetrically, so the gateway and the MCP servers share a
  secret.
