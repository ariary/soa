# Benchmark: BufferZoneCorp Malicious Packages

First benchmark of soa's LLM analysis pipeline against a curated set of malicious
and benign packages from the [BufferZoneCorp](https://github.com/BufferZoneCorp)
test corpus.

## Setup

- **LLM:** Ollama / llama3 (8B, Q4_0) — running locally
- **Rules:** `max_age=disabled`, `min_versions=disabled`, `analysis=enabled`
- **Date:** 2026-04-24

The corpus contains Go modules and Ruby gems with known ground-truth labels
(malicious vs benign). All malicious packages exfiltrate to `localhost:9999` only —
they are safe test specimens, not real malware.

## Results

### Go modules (10 packages, documented versions)

| Module | Version | Ground Truth | Scan | Verdict |
|--------|---------|-------------|------|---------|
| go-envconfig | v0.1.0 | benign | ALLOWED | TN |
| log-core | v0.2.0 | benign | ALLOWED | TN |
| log-core | v0.1.0 | malicious | BLOCKED | TP |
| go-metrics-sdk | v0.1.0 | malicious | BLOCKED | TP |
| go-weather-sdk | v0.1.0 | malicious | BLOCKED | TP |
| go-retryablehttp | v0.1.0 | malicious | BLOCKED | TP |
| go-stdlib-ext | v0.1.0 | malicious | BLOCKED | TP |
| grpc-client | v0.1.0 | malicious | BLOCKED | TP |
| net-helper | v0.1.0 | malicious | BLOCKED | TP |
| config-loader | v0.1.0 | malicious | BLOCKED | TP |

**Go accuracy: 10/10 (100%)** — 8 TP, 2 TN, 0 FP, 0 FN

### Ruby gems (7 packages)

| Gem | Version | Ground Truth | Scan | Verdict |
|-----|---------|-------------|------|---------|
| knot-rack-session-store | 2.1.4 | malicious | BLOCKED (code) | TP |
| knot-devise-jwt-helper | 1.0.7 | malicious | BLOCKED (code) | TP |
| knot-rails-assets-pipeline | 6.1.11 | malicious | BLOCKED (code) | TP |
| knot-activesupport-logger | 7.1.6 | malicious | BLOCKED (code) | TP |
| knot-rspec-formatter-json | 3.13.5 | malicious | BLOCKED (code) | TP |
| knot-simple-formatter | 1.0.0 | benign | BLOCKED (release) | FP |
| knot-date-utils-rb | 1.0.0 | benign | ALLOWED | TN |

**Ruby accuracy: 6/7 (86%)** — 5 TP, 1 TN, 1 FP, 0 FN

### Combined

| Metric | Value |
|--------|-------|
| True Positives | 13 |
| True Negatives | 3 |
| False Positives | 1 |
| False Negatives | 0 |
| **Precision** | 93% (13/14) |
| **Recall** | 100% (13/13) |
| **Accuracy** | 94% (16/17) |

## False Positive Analysis

`knot-simple-formatter@1.0.0` — benign gem with an `extconf.rb` C extension and
`at_exit` cleanup hook. The **code analyzer passed it**, but the **release analyzer**
flagged "suspicious release signals", likely because the gem is new, has a single
version, and comes from a young RubyGems account. This is a release-metadata
heuristic FP, not a code-analysis FP.

**Mitigation applied:** added guidance to the release system prompt clarifying that
being new/single-maintainer is not inherently suspicious without corroborating signals.

## Version Evolution (Go, additional versions)

The corpus includes additional versions (v0.2.0–v0.4.0) for most Go modules. These
don't have documented ground-truth labels but were all BLOCKED by the code analyzer.
The one notable result:

- **log-core v0.1.0** → BLOCKED (malicious), **v0.2.0** → ALLOWED (benign) — the
  scanner correctly distinguished the malicious version from the clean follow-up.

## Notes

- **Go module proxy gap:** BufferZoneCorp modules are not indexed by `proxy.golang.org`.
  Testing required a temporary code patch to point the server at a local file server
  serving the Go module cache. Ruby gems worked without any workaround.
- **LLM JSON reliability:** llama3 8B sometimes returns `"evidence": "text"` instead of
  `"evidence": ["text"]`. The `FlexibleStrings` custom unmarshaler handles both forms.
- **Throughput:** ~30s per module analysis with llama3 8B on Apple Silicon (M-series).
