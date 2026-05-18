# soa & tonga

*Tonga soa* — welcome, in Malagasy. 🇲🇬

Your packages go through customs now.

## The gist

Two binaries, one job: stop malicious dependencies before they reach your machine.

- **`soa`** — the client. Wraps your package manager commands and intercepts every dependency download through a local proxy. Before any archive reaches your machine, it gets checked against a security policy server. If the package is too fresh, too sketchy, or fails analysis, it gets stopped at the border.
- **`tonga`** — the backend. Runs the check server and the advisory feed.

Think [supply chain attacks](https://github.com/ariary/malicious-go-package): a dependency you've never heard of sneaks into your build and runs arbitrary code on install. `soa` catches it before it reaches your machine.

## Show me

Terminal 1, start the check server:
```bash
tonga serve
```

Terminal 2, prefix any command with `soa`:
```bash
soa make build
```

That's it. `soa` doesn't care what you run. It sets up a local proxy, rewires the right env vars, and checks every dependency download before it lands. You'll see this while it works:

```
[soa] ⠋ scanning github.com/gin-gonic/gin@v1.9.1
[soa] ✓ github.com/gin-gonic/gin@v1.9.1 allowed
```

If something gets blocked:
```
[soa] ✗ github.com/sketchy/lib@v0.0.1 blocked: published 2 days ago
```

`soa` wraps anything: your toolchain, your aliases, your scripts:
```bash
soa go test ./...
soa npm install express
soa pip install requests
soa bundle install
soa ./scripts/deps.sh   # anything that pulls packages
```

## Supported ecosystems

| Ecosystem | Env var hijacked |
|---|---|
| Go | `GOPROXY` |
| npm | `npm_config_registry` |
| pip | `PIP_INDEX_URL` |
| RubyGems | `GEM_HOST` |

All ecosystems are active by default. Disable one for a single run:
```bash
soa --go=false npm install   # only intercept npm, leave Go alone
```

Each ecosystem is a `Manager`, a single interface implementation. Adding one is straightforward.

## Get it

```bash
go install github.com/ariary/soa/cmd/soa@latest
go install github.com/ariary/soa/cmd/tonga@latest
```

> Requires **Go 1.25.5+**. See [docs/install.md](docs/install.md) for PATH setup, remote tonga, team deployment, and more.

## Under the hood

```
you ─► soa ─► local proxy ─► tonga serve ─► allow/block
                   │                              │
                   │ if allowed                   │
                   ▼                              │
              upstream registry ◄────────────────┘
```

1. `soa` detects active ecosystems and reads their upstream registry (e.g. `GOPROXY` for Go, `npm_config_registry` for npm)
2. Starts a local HTTP proxy and overrides the relevant env vars to point to it
3. Spawns your command with the modified environment
4. For every source archive download, asks the check server (`tonga serve`)
5. Metadata requests pass through (no delay on lookups)
6. When done, the proxy shuts down and `soa` exits with your command's exit code

## Rules

The check server (`tonga serve`) enforces rules in order. A package must pass all enabled rules to be allowed.

**Known malware**: checks the package against known malicious package databases before anything else. If the package+version is a known supply chain attack, it gets blocked instantly. Always on, no config needed.
- [osv.dev](https://osv.dev) MAL-* advisories ([OpenSSF](https://github.com/ossf/malicious-packages)) — always active, covers all GHSA MALWARE entries plus ~190k more from other detection sources
- [GitHub Advisory Database](https://github.com/advisories) MALWARE classification — optional, enabled when `GITHUB_TOKEN` is set. Only useful if the ~10-minute propagation delay to osv.dev matters for your threat model

**Max age**: the package version must have been published at least N days ago. Catches brand new malicious releases before they gain trust. Enabled by default, 7 days.

**Min versions**: the package must have at least N released versions. A single version package with no history is suspicious. Enabled by default, minimum 2.

**Analysis**: send the package to an LLM for malware detection. Code analysis and release metadata checks run in parallel. If either flags the package, it gets blocked immediately. Off by default. See [docs/malware-analysis.md](docs/malware-analysis.md) for setup.

## Feed

`tonga feed` monitors for new malicious package advisories and prints them to your terminal in real-time:

```bash
tonga feed
```

```
[tonga] feed started (polling every 5m, sources: osv.dev + GHSA)
[MAL-2025-49286] npm / gunpowder-ghost@209.0.0, 217.0.0, 213.0.0, 212.0.0, 211.0.0, 225.0.0
  Malicious code in gunpowder-ghost (npm)
  2026-04-30  https://osv.dev/vulnerability/MAL-2025-49286
---
[GHSA-5w4c-85pv-cwhv] npm / tanstack@2.0.7
  Malware in tanstack
  2026-04-29  https://github.com/advisories/GHSA-5w4c-85pv-cwhv
---
```

Filter by ecosystem and tune the interval:
```bash
tonga feed --ecosystem npm,pypi --interval 1m
```

Two sources, deduplicated (see [docs/osv-vs-ghsa.md](docs/osv-vs-ghsa.md) for the full comparison):
- **osv.dev MAL-*** ([OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)) — always on, no token needed. This is a superset of GHSA MALWARE.
- **GitHub Advisory Database** (GHSA `MALWARE` classification) — optional, enabled when `GITHUB_TOKEN` is set. Gives a ~10-minute head start on GHSA-sourced advisories only.

State is persisted across restarts — you won't see the same advisory twice.

## Knobs

Config lives at `~/.config/soa/config.yaml`:

```yaml
check_url: "http://localhost:9090"
proxy:
  port: 8080
poll_interval: "500ms"
check_timeout: "30s"
server:
  port: 9090
  cache_path: "~/.config/soa/approved.json"
  rules:
    max_age:
      enabled: true
      min_days: 7
    min_versions:
      enabled: true
      count: 2
    analysis:
      enabled: false
      provider: "ollama"
      model: "llama3"
```

Every value can be overridden with env vars:

| Config | Env var | Default |
|---|---|---|
| `check_url` | `SOA_CHECK_URL` | `http://localhost:9090` |
| `proxy.port` | `SOA_PROXY_PORT` | `8080` |
| `check_timeout` | `SOA_CHECK_TIMEOUT` | `30s` |
| `server.port` | `SOA_SERVER_PORT` | `9090` |
| `server.cache_path` | `SOA_SERVER_CACHE_PATH` | `~/.config/soa/approved.json` |
| `rules.max_age.enabled` | `SOA_RULE_MAX_AGE_ENABLED` | `true` |
| `rules.max_age.min_days` | `SOA_RULE_MAX_AGE_MIN_DAYS` | `7` |
| `rules.min_versions.enabled` | `SOA_RULE_MIN_VERSIONS_ENABLED` | `true` |
| `rules.min_versions.count` | `SOA_RULE_MIN_VERSIONS_COUNT` | `2` |
| `rules.analysis.enabled` | `SOA_RULE_ANALYSIS_ENABLED` | `false` |
| `rules.analysis.provider` | `SOA_ANALYSIS_PROVIDER` | `ollama` |
| `rules.analysis.model` | `SOA_ANALYSIS_MODEL` | `llama3` |

See [docs/malware-analysis.md](docs/malware-analysis.md) for the full analysis config reference.

## FAQ

**What if the check server is down?**
All packages are blocked. `soa` fails closed. No free passes.

**Does this slow things down?**
Only source archive downloads go through the check. Metadata requests flow straight through. If the package is in the approved cache, the check is instant.

**what is the added-value of `tonga feed`?**
using `soa`+`tonga serve` protects you at the *moment of import*, tonga feed protects you for the entire duration the code sits in your environment (help detecting malicious dep for the ones already in approved cache). It’s the difference between checking an ID at the door and having a system that flags if that person’s "clearance" is revoked later.


**Can I use my own check server?**
Yes. Point `check_url` to any server that speaks the [check API](pkg/checkapi/checkapi.go). `tonga serve` is just a reference implementation.

**What does "tonga soa" mean?**
Welcome, in Malagasy. 🇲🇬
