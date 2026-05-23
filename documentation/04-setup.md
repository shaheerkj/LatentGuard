# Setup

## Requirements

- Docker Desktop (Windows / Mac) **or** Docker Engine 24+ with Compose
  plugin (Linux)
- ~4 GB free RAM (TensorFlow + Coraza + Mongo + Juice Shop together)
- ~3 GB disk for images
- An open `:3000`, `:8000`, `:8080`, `:8443`, `:27017` on the host

That's it. No local Python or Go required to *run* the stack; you need
those only if you want to retrain models or rebuild the proxy outside
Docker.

## Bring the stack up

```bash
git clone <repo>
cd LatentGuard
docker compose -f infra/docker-compose.yml up -d --build
```

First run takes ~5 minutes (image builds + model download +
threat-intel fetch). Subsequent starts are ~30 seconds.

Containers come up in this order: `mongo` → `juiceshop` → `ml` →
`proxy` → `dashboard`. The ML service warms up TensorFlow and HDBSCAN
in the background — log line `Application startup complete` means it's
ready to take requests.

## Verify the stack

```bash
# 1. health
curl -s http://localhost:8000/healthz
curl -s http://localhost:8080/__healthz

# 2. log in (gets a JWT)
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
    -H 'Content-Type: application/json' \
    -d '{"username":"shaheerkj","password":"v59q1rg8EOfykTXUUp1b"}' \
    | python -c "import json,sys; print(json.load(sys.stdin)['token'])")

# 3. operator endpoints (require the token)
curl -s http://localhost:8000/api/metrics -H "Authorization: Bearer $TOKEN"
curl -s http://localhost:8080/__threatintel -H "Authorization: Bearer $TOKEN"

# 4. dashboard
open http://localhost:3000
```

## Default credentials

| Field | Value |
|---|---|
| Username | `shaheerkj` |
| Password | `v59q1rg8EOfykTXUUp1b` |

**Change them for any non-local deployment.** The compose file
documents how — override `ADMIN_USER` and `ADMIN_PASSWORD_HASH`
(bcrypt cost ≥12) and pick a long random `JWT_SECRET`.

## Fire some attacks

```bash
python attacks/run_attacks.py --proxy http://127.0.0.1:8080 --sleep-ms 3
```

Runs the 141-payload red-team battery (19 attack classes) and prints a
summary. Expected: ~83% detection rate on blocks, 0% false positives
on the 12 benign Juice Shop flows.

## Tear down

```bash
docker compose -f infra/docker-compose.yml down            # keep volumes
docker compose -f infra/docker-compose.yml down -v         # nuke audit log + models too
```

## When to rebuild

| Change | Command |
|---|---|
| Edit Python in `ml/` | `docker compose -f infra/docker-compose.yml up -d --build ml` |
| Edit Go in `proxy/` | `docker compose -f infra/docker-compose.yml up -d --build proxy` |
| Edit dashboard files | Hard refresh browser — nginx serves the host folder read-only, no rebuild needed |
| Change env vars in compose | `docker compose ... up -d --force-recreate <svc>` (no `--build` if code unchanged) |
| Change a rules file under `proxy/rules/` | `--build proxy` (rules are baked into the image) |

Common pitfall: editing code but only running `up -d` without
`--build` leaves the old image running. The container restarts but
the new code never lands.
