# VLESS Personal Feed — baaltazar25.github.io

Collect public VLESS subscriptions, validate the actual VLESS+TLS/REALITY connection using **Xray-core**, publish plain URI/Base64 feeds through **GitHub Pages**. Schedule: `11,41 * * * *` (roughly every 30 minutes, UTC).

## Quick setup

1. Create or use the **PUBLIC** repository `baaltazar25/baaltazar25.github.io`. If GitHub returns 404, verify the exact username/repo, or create it first.
2. Copy project files into the **repository root**, keeping `.github/workflows/update-vless.yml`. If the repo contains an existing website, inspect conflicts before copying (especially existing workflows and site build pipelines).
3. In GitHub: **Settings → Pages → Build and deployment → Source: GitHub Actions**. Do not choose "Deploy from a branch": commits pushed using `GITHUB_TOKEN` will not trigger a Pages rebuild.
4. In GitHub: **Actions → Update personal VLESS feed → Run workflow**. Later runs occur via schedule on the default branch.
5. After successful workflow, feed URLs should be:

| Output | URL | Meaning |
| --- | --- | --- |
| Plain subscription | `https://baaltazar25.github.io/feeds/vless.txt` | Only verified nodes (Xray+HTTPS 204) |
| Base64 subscription | `https://baaltazar25.github.io/feeds/vless_base64.txt` | Same nodes as Base64 |
| REALITY subset | `https://baaltazar25.github.io/feeds/vless_reality.txt` | Only verified REALITY nodes |
| Russia-oriented sources | `https://baaltazar25.github.io/feeds/ru_verified.txt` | Verified nodes originating from RU-focused sources |
| Whitelist source | `https://baaltazar25.github.io/feeds/ru_whitelist_verified.txt` | Verified nodes from whitelist-focused sources |
| Unverified candidates | `https://baaltazar25.github.io/feeds/ru_candidates_unverified.txt` | NOT verified; testing list only |
| Status | `https://baaltazar25.github.io/feeds/status.json` | Timestamp, counts, source health |
| Overview | `https://baaltazar25.github.io/feeds/` | Links and status page |

**Caution:** the GitHub-hosted runner is outside Russia. Positive health checks do **not** establish that a node works through RKN/TSPU filters or Russian mobile operator allowlists. For accurate RF testing, use a self-hosted runner in the target ISP and compare results. See details below.

## How checking works

The collector pulls 8 HTTP(S) sources in parallel. VLESS entries are extracted from plain-text and Base64 lists, normalized, validated and deduplicated. It prioritizes Russian allowlist and other Russia-oriented sources (2:2:1 round-robin), with 240 candidate tests by default. Each candidate spawns a local Xray-core process on an ephemeral SOCKS5 port. `httpx[socks]` requests an HTTPS `generate_204` endpoint **through that SOCKS5 proxy**, with certificate validation enabled. A node is verified only if the remote HTTPS response is `204`. A TCP-connect alone is never treated as a pass.

The GitHub API's release-asset SHA256 digest is checked before unpacking the official Xray binary. The collector also blocks literal non-global IP targets, rejects disabled TLS verification, and suppresses full URI logging. DNS-name targets cannot be fully prevented from resolving to internal addresses without additional safeguards; use only trusted subscription lists and a controlled runner.

Supported URI combinations: VLESS+TLS or VLESS+REALITY; `tcp/raw`, `ws`, `grpc`, `xhttp`, `httpupgrade`; mainstream share-link parameters. The parser does not fully cover proprietary and newer Xray URI extensions. If a node uses an unsupported parameter, its check may fail even when the node works in an up-to-date client.

## Configuration

* `sources.json`: add trusted HTTPS subscriptions using `name`, `group` (`ru_whitelist`, `ru_general`, `global`) and `url`.
* `MAX_CANDIDATES`: how many nodes to probe per cycle, default **240**.
* `MAX_WORKERS`: parallel Xray instances, default **12**; max 32.
* `PROBE_TIMEOUT`: per HTTP attempt (seconds), default **9**.
* `XRAY_BIN`: path to executable.

A full probing cycle can run for multiple minutes. GitHub scheduled workflows are **best-effort**, not a hard real-time SLA; some runs may start late or be skipped. Scheduled workflows in public repos can be disabled after prolonged inactivity; check GitHub Actions settings if updates stop. On complete source outage or zero passing nodes, collector fails rather than overwriting a previously good feed with an empty list.

## Local smoke tests

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

To run the real collector on Linux:

```bash
python scripts/install_xray.py
XRAY_BIN=./bin/xray MAX_CANDIDATES=30 python collector.py
```

## GitHub Pages integration note

The included workflow explicitly deploys a static snapshot of the **repository root** and the generated `feeds/` directory using `actions/deploy-pages`. This ensures the Pages URL actually updates even though the generated feed commit uses `GITHUB_TOKEN`. It is suitable for a **static website**. If your existing GitHub Pages website uses Jekyll, Hugo, Next.js, or another build system, merge the feed into its existing build output instead of using the template's generic `rsync` step; otherwise that site's rendering may change.

## Operational limitations and security

- Source feed servers are untrusted. Avoid public free exit nodes for confidential sessions, authentication, internal systems, or enterprise traffic.
- Running arbitrary proxy configurations tests the remote endpoints. The scanner limits concurrency; do not maximize it indiscriminately.
- Publicly publishing the feed exposes the same access keys to others, hastening abuse and invalidation.
- `ru_candidates_unverified.txt` is **not** a list of working nodes; it is intentionally separate.
- Source labels/locations are **provenance**, not independent network/geolocation measurements.
- To test blocks **inside Russia**, use a probe host in the actual Russian fixed/mobile network. Do not misrepresent Github-hosted check results as RF checks.
- The template does not create a repo or modify your GitHub account automatically.
