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

## OWASP CRS — pinned to v4.7.0

The CRS bundle under `90-crs/` is **vendored into the repo** at version
`4.7.0` (see `90-crs/VERSION`) so the build is reproducible: nothing
fetches from `coreruleset/coreruleset` at Docker build time, and a
disconnected build still works. The pinned version is also recorded in
the `crs-setup.conf` header line `# OWASP CRS ver.4.7.0`.

To upgrade to a newer CRS release:

```bash
CRS_VERSION=v4.8.0 ./scripts/fetch-crs.sh
echo 4.8.0 > rules/90-crs/VERSION
# review the diff -- new CRS releases occasionally break custom rule IDs
git add rules/90-crs
```

Bump deliberately, not by accident — the fetch script's default
`CRS_VERSION` is the pinned version, so a bare re-run is safe, but
relying on "latest" silently shifts the detection floor.
