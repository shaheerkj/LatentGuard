# proxy/rules — SecLang rule files for Coraza

Coraza loads every `*.conf` file in this directory at startup. Files are read
in lexicographic order, so prefix new rule packs with a number to control
ordering.

## Layout convention

| Prefix | Owner | Purpose |
| --- | --- | --- |
| `00-` | LatentGuard | Engine setup (`SecRuleEngine`, body limits, default actions) |
| `10-` | LatentGuard | Hand-written baseline (SQLi/XSS/LFI/RCE) |
| `90-` | OWASP CRS | The Core Rule Set bundle (fetched separately) |
| `99-` | LatentGuard | AI-generated rules from M9 once approved by HITL |

## Rule ID space

| Range | Owner |
| --- | --- |
| `900000–999999` | OWASP CRS (do not reuse) |
| `1000000–1099999` | LatentGuard hand-written baseline |
| `2000000+` | AI-generated rules (M9) |

## Fetching OWASP CRS

```
./scripts/fetch-crs.sh
```

This downloads the latest stable CRS release and copies the rules into
`proxy/rules/90-crs/`. Re-run to update.
