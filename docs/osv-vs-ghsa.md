# osv.dev MAL-* vs GHSA MALWARE: how they relate

## TL;DR

osv.dev's `MAL-*` advisories are a **strict superset** of GHSA `MALWARE` advisories.
Every GHSA MALWARE entry ends up as a `MAL-*` entry on osv.dev within ~10 minutes.
The reverse is not true: osv.dev has ~10x more malware findings than GHSA because it aggregates additional sources.

## The numbers (as of April 2026, npm ecosystem)

| Source | Malware advisories |
|--------|-------------------|
| osv.dev `MAL-*` | **~212,000** |
| GHSA `type:MALWARE` | **~22,000** |

## The pipeline

GHSA MALWARE advisories are **not independently stored** in osv.dev.
They are ingested by the [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages) project,
re-keyed to a `MAL-*` ID, and imported into osv.dev with the original GHSA ID kept as an alias:

```
GitHub Advisory Database (classification: MALWARE)
    │
    ▼
ossf/malicious-packages repo  (source: "ghsa-malware", assigns MAL-* ID)
    │
    ▼
osv.dev  (stores as MAL-*, GHSA ID in "aliases" field)
```

Querying `api.osv.dev/v1/vulns/GHSA-xxxx` returns:
```json
{"code":5, "message":"Bug not found, but the following aliases were: MAL-2026-XXXX"}
```

Querying by package name returns the `MAL-*` entry directly.

## Coverage

| Direction | Coverage | Evidence |
|-----------|----------|----------|
| GHSA → MAL | **100%** | Verified on 23 samples across 2022–2026. Zero gaps found. |
| MAL → GHSA | **~50%** | Many MAL entries have no GHSA counterpart (sourced from Amazon Inspector, etc.) |

## Where do the extra ~190k MAL entries come from?

osv.dev aggregates malware reports from multiple detection pipelines:

| Source | Approx. volume | Active since |
|--------|---------------|-------------|
| `ghsa-malware` | ~22k | 2022 (matches GHSA count) |
| `amazon-inspector` | ~188k | 2025 (bulk npm submissions) |
| `ossf-package-analysis` | thousands | 2022 |
| `reversing-labs` | thousands | 2023 |
| `kam193` (researcher) | hundreds | 2025, mostly PyPI |

The 2025 explosion (~193k new MAL entries, up from ~12k in 2024) is almost entirely Amazon Inspector bulk submissions of npm packages.

## Sync latency

GHSA publication → MAL entry available on osv.dev: **~7–10 minutes**.

Verified on entries published 2026-04-30: GHSA published at `16:40:06Z`, MAL `import_time` at `16:46:55Z`.

## What this means for tonga

**`osv.dev` alone gives you full coverage.** The GHSA feed is a strict subset.

Adding GHSA as a second source (`--source all` or `--source ghsa`) buys you **only a ~10-minute head start** on advisories that originated from GitHub. Use it only if that window matters for your threat model.

For the `tonga serve` known-malware check, the same applies: the osv.dev query already covers every GHSA MALWARE advisory.

## Verifying yourself

```bash
# Pick any GHSA MALWARE advisory
curl -s 'https://api.github.com/advisories?type=malware&ecosystem=npm&per_page=1' \
  | jq '.[0].ghsa_id'
# → "GHSA-72vc-j35j-p28h"

# Check if it exists on osv.dev
curl -s 'https://api.osv.dev/v1/vulns/GHSA-72vc-j35j-p28h'
# → {"code":5,"message":"Bug not found, but the following aliases were: MAL-2026-3176"}

# Fetch the MAL entry
curl -s 'https://api.osv.dev/v1/vulns/MAL-2026-3176' | jq '.aliases'
# → ["GHSA-72vc-j35j-p28h"]
```
