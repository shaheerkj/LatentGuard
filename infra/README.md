# infra/ — local development stack

`docker-compose.yml` brings up the full LatentGuard stack:

| Service | Port (host) | Purpose |
| --- | --- | --- |
| `mongo` | 27017 | Audit + rules + metrics storage (M7) |
| `dvwa` | (internal) | Vulnerable target app — traffic source for testing |
| `ml` | 8000 | FastAPI scoring service (M4–M6, M8, M9, M11) |
| `proxy` | 8080 | Go reverse proxy with Coraza WAF (M1–M3) |
| `dashboard` | 3000 | Static UI (M10) |

## Quick start

```
cd infra
docker compose up -d --build
```

Then point a browser at:

- `http://localhost:8080/` — protected DVWA via the proxy
- `http://localhost:3000/` — operator dashboard
- `http://localhost:8000/healthz` — ML service liveness

## Tear down

```
docker compose down -v
```
