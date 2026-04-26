# storage/ — MongoDB schemas, indexes, retention

SRS module **M7 (Storage and audit logging)**.

Collections (planned):

- `requests`     — every intercepted request + decision (90-day retention).
- `rule_hits`    — per-request rule match details.
- `rules_queue`  — AI-generated rule drafts pending HITL review.
- `audit_events` — admin/auth/config changes (365-day retention).
- `metrics_5m`   — pre-aggregated rollups for the dashboard.

This directory holds the schema + index definitions and retention scripts.
The actual storage runs in the `mongo` container from `infra/docker-compose.yml`.
