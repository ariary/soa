# 🥢 soa

Your packages go through customs now.

## The gist

`soa` wraps your package manager commands and intercepts every dependency download through a local proxy. Before any archive reaches your machine, it gets checked against a security policy server. If the package is too fresh, too sketchy, or fails analysis, it gets stopped at the border.

Think [supply chain attacks](https://github.com/ariary/malicious-go-package): a dependency you've never heard of sneaks into your build and runs arbitrary code on install. `soa` catches it before it reaches your machine.

## Show me

Terminal 1, start the check server:
```bash
soa serve
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

| Ecosystem | Env var hijacked | Detection |
|---|---|---|
| Go | `GOPROXY` | `go.mod` in working directory |
| npm | `npm_config_registry` | `package.json` in working directory |
| pip | `PIP_INDEX_URL` | `requirements.txt` or `setup.py` in working directory |
| RubyGems | `GEM_HOST` | `Gemfile` in working directory |

Each ecosystem is a `Manager`, a single interface implementation. Adding one is straightforward.

Disable an ecosystem for a single run:
```bash
soa --go=false npm install   # only intercept npm, leave Go alone
```

## Get it

```bash
go install github.com/ariary/soa/cmd/soa@latest
```

## Under the hood

```
you ─► soa ─► local proxy ─► check server ─► allow/block
                   │                                   │
                   │ if allowed                        │
                   ▼                                   │
              upstream registry ◄───────────────────┘
```

1. `soa` detects active ecosystems and reads their upstream registry (e.g. `GOPROXY` for Go, `npm_config_registry` for npm)
2. Starts a local HTTP proxy and overrides the relevant env vars to point to it
3. Spawns your command with the modified environment
4. For every source archive download, asks the check server
5. Metadata requests pass through (no delay on lookups)
6. When done, the proxy shuts down and `soa` exits with your command's exit code

## Rules

The check server enforces rules in order. A package must pass all enabled rules to be allowed.

**Known malware**: checks the package against known malicious package databases before anything else. If the package+version is a known supply chain attack, it gets blocked instantly. Always on, no config needed.
- [osv.dev](https://osv.dev) MAL-* advisories ([OpenSSF](https://github.com/ossf/malicious-packages)) — always active
- [GitHub Advisory Database](https://github.com/advisories) MALWARE classification — enabled when `GITHUB_TOKEN` is set

**Max age**: the package version must have been published at least N days ago. Catches brand new malicious releases before they gain trust. Enabled by default, 7 days.

**Min versions**: the package must have at least N released versions. A single version package with no history is suspicious. Enabled by default, minimum 2.

**Analysis**: send the package to an LLM for malware detection. Code analysis and release metadata checks run in parallel. If either flags the package, it gets blocked immediately. Off by default. See [docs/malware-analysis.md](docs/malware-analysis.md) for setup.

## Feed

`soa feed` monitors for new malicious package advisories and prints them to your terminal in real-time:

```bash
soa feed
```

```
[soa] feed started (polling every 5m, sources: osv.dev + GHSA)
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
soa feed --ecosystem npm,pypi --interval 1m
```

Two sources, deduplicated:
- **osv.dev MAL-*** ([OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)) — always on, no token needed
- **GitHub Advisory Database** (GHSA `MALWARE` classification) — enabled when `GITHUB_TOKEN` is set

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

**Can I use my own check server?**
Yes. Point `check_url` to any server that speaks the [check API](pkg/checkapi/checkapi.go). The built in `soa serve` is just a reference implementation.

**What does "soa" mean?**
It's Malagasy. Look it up. 🇲🇬
