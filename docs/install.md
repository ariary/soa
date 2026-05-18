# Install & setup

## Install

### Prerequisites

**Go 1.25.5+** — check with `go version`.

### With `go install`

```bash
go install github.com/ariary/soa/cmd/soa@latest
go install github.com/ariary/soa/cmd/tonga@latest
```

Both binaries land in your Go bin directory. Make sure it's in your `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

Add this to your shell profile (`~/.bashrc`, `~/.zshrc`, …) to make it permanent.

### From source

```bash
git clone https://github.com/ariary/soa.git
cd soa
make build
# produces ./soa and ./tonga in the current directory
mv soa tonga /usr/local/bin/
```

### Verify

```bash
soa --help
tonga --help
```

## Setup

### Local (default)

The simplest setup: run both on the same machine. Open two terminals:

```bash
# terminal 1 — start the check server
tonga serve
```

```bash
# terminal 2 — run any command through soa
soa go build ./...
```

That's it. By default `soa` sends checks to `http://localhost:9090`, which is where `tonga serve` listens.

### Remote tonga

If `tonga` runs on a different machine (a shared server, a CI host, …), point `soa` to it:

```bash
export SOA_CHECK_URL="http://tonga.internal:9090"
soa npm install
```

Or set it permanently in `~/.config/soa/config.yaml`:

```yaml
check_url: "http://tonga.internal:9090"
```

On the remote side, start tonga on the desired port:

```bash
# on the remote machine
tonga serve --port 9090
```

`tonga` binds to all interfaces by default, so it will be reachable from other machines. Make sure the port is accessible (firewall, security group, etc.).

With this setup you only need `soa` installed on developer machines — `tonga` lives on the server.

### Custom ports

If the defaults (`9090` for tonga, `8080` for the local proxy) conflict with something:

```bash
# change tonga's port
tonga serve --port 7070

# tell soa where tonga is + change the local proxy port
export SOA_CHECK_URL="http://localhost:7070"
export SOA_PROXY_PORT=7071
soa make build
```

Or in config:

```yaml
check_url: "http://localhost:7070"
proxy:
  port: 7071
```

### Team setup

A typical team deployment:

1. Deploy `tonga serve` on a shared host (e.g. `tonga.internal:9090`)
2. Each developer installs `soa` only
3. Each developer adds to their shell profile:
   ```bash
   export SOA_CHECK_URL="http://tonga.internal:9090"
   ```
4. Everyone wraps their package manager commands with `soa`:
   ```bash
   soa go build ./...
   soa npm install
   ```

The shared tonga server maintains a single approved cache, so once a package version is checked and allowed, every team member benefits immediately.

### GITHUB_TOKEN (optional)

Setting `GITHUB_TOKEN` on the machine running `tonga` enables two extras:

- **Known malware checks** gain a second source (GitHub Advisory Database) in addition to osv.dev — gives a ~10-minute head start on GHSA-sourced advisories
- **`tonga feed`** can include GHSA as a feed source

```bash
export GITHUB_TOKEN="ghp_..."
tonga serve
```

Without it, everything still works — osv.dev already covers all GHSA MALWARE entries.
