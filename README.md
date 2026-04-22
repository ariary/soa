# 🛃 soa

Your packages go through customs now.

## The gist

`soa` wraps your package manager commands and intercepts every dependency download through a local proxy. Before any archive reaches your machine, it gets checked against a security policy server. If the package is too fresh, too sketchy, or fails analysis — it gets stopped at the border.

Think [supply-chain attacks](https://github.com/ariary/malicious-go-package) — a dependency you've never heard of sneaks into your build and runs arbitrary code on install. `soa` catches it before it reaches your machine.

Works with Go today. npm and pip are next in line.

## Show me

Prefix any command with `soa`:
```bash
soa make build
```

That's it. `soa` sets up a proxy, rewires the right env vars, and checks every dependency download before it lands. You'll see this while it works:

```
[soa] ⠋ scanning github.com/gin-gonic/gin@v1.9.1
[soa] ✓ github.com/gin-gonic/gin@v1.9.1 allowed
```

If something gets blocked:
```
[soa] ✗ github.com/sketchy/lib@v0.0.1 blocked: published 2 days ago
```

`soa` wraps anything — your toolchain, your aliases, your scripts:
```bash
soa go test ./...
soa gogo build          # custom alias? no problem
soa ./scripts/deps.sh   # anything that pulls packages
```

### Running the check server

`soa` sends checks to whatever `check_url` points to in your config. A reference implementation ships with the binary:

```bash
soa serve
```

This starts a check server that blocks packages published less than 7 days ago. Point `check_url` at any endpoint that speaks the [check API](pkg/checkapi/checkapi.go) — your own, a shared team server, a cloud service.

## Get it

```bash
go install github.com/ariary/soa/cmd/soa@latest
```

## Under the hood

```
you ─► soa ─► local proxy ─► check server ─► allow/block
                   │                              │
                   │ if allowed                   │
                   ▼                              │
              upstream proxy ◄────────────────────┘
              (proxy.golang.org)
```

1. `soa` reads your `GOPROXY` to find the real upstream
2. Starts a local HTTP proxy and overrides `GOPROXY` to point to it
3. Spawns your command with the modified environment
4. For every `.zip` request (actual source code downloads), asks the check server
5. `.info` and `.mod` requests pass through — no delay on metadata
6. When done, the proxy shuts down and `soa` exits with your command's exit code

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
  max_age_days: 7
```

Every value can be overridden with env vars:

| Config | Env var | Default |
|---|---|---|
| `check_url` | `SOA_CHECK_URL` | `http://localhost:9090` |
| `proxy.port` | `SOA_PROXY_PORT` | `8080` |
| `check_timeout` | `SOA_CHECK_TIMEOUT` | `30s` |
| `server.port` | `SOA_SERVER_PORT` | `9090` |
| `server.max_age_days` | `SOA_SERVER_MAX_AGE_DAYS` | `7` |

Disable an ecosystem for a single run:
```bash
soa --go=false npm install foo   # don't intercept Go, only npm (future)
```

## FAQ

**What if I trust everything?**
Don't use soa then. We respect your bravery.

**What if the check server is down?**
All packages are blocked. soa fails closed — no free passes.

**Does this slow things down?**
Only `.zip` downloads go through the check. Metadata (`.info`, `.mod`) flows straight through. If the package is in the approved cache, the check is instant.

**Can I use my own check server?**
Yes. `soa` talks to whatever `check_url` points to. The built-in `soa serve` is just a reference implementation — swap it for anything that speaks the [check API](pkg/checkapi/checkapi.go).

**What's "soa" mean?**
It's Malagasy. Look it up. 🇲🇬
