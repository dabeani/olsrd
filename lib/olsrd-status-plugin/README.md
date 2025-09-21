# olsrd-status-plugin

This plugin provides HTTP status endpoints by reading OLSRd in-memory
data structures. Important notes for developers and packagers:

- The plugin intentionally depends on core olsrd implementations (for
  example `autobuf` and other internal helpers). It is not intended to
  run standalone — it is expected to be loaded by the `olsrd` daemon,
  which provides the canonical implementations of required symbols at
  runtime (this follows the same approach as `jsoninfo`/`txtinfo`).

- Do not add local copies of core implementation files (e.g. `autobuf.c`)
  into this plugin. Doing so can cause duplicate-symbol collisions when
  the plugin is loaded into the running daemon.

Build: `make -C lib/olsrd-status-plugin`
# olsrd-status-plugin

Note: this plugin is now included in the top-level build. You can build it via the repository root with `make libs`, or build/install locally from the plugin directory as shown below.

Light‑weight HTTP status / diagnostics plugin for legacy **olsrd (v1)** and **olsr2** daemons. It exposes a small embedded web UI plus JSON APIs that aggregate and normalize link, neighbor, route, topology, device discovery and system information into a single, cache‑friendly interface for monitoring tools or browsers.

## Key Capabilities
* Unified detection of running OLSR daemons (olsrd v1 and olsr2) inside classic systems, EdgeRouters and Linux containers.
* Normalized per‑neighbor link table with derived fields: `routes`, `nodes`, `is_default`, reverse DNS of peers.
* Route & topology correlation (counts per neighbor) with multi‑stage fallback (routes -> topology -> neighbors two‑hop -> pattern scan) so counts rarely stay zero.
* Neighbor normalization (olsr2 JSON or legacy link output) to a consistent shape for the UI.
* Device discovery aggregation:
    * Primary: `ubnt-discover` binary (JSON mode)
    * Fallbacks: cached dump, active broadcast probe, ARP table synthesis
    * Reverse DNS enrichment.
* Dynamic `nodedb.json` style output (object map form) synthesized from real sources with validation & ARP fallback – keeps external scripts compatible.
* Connection / MAC / IP correlation via simple `/connections.json` (bridges, interfaces, learned MACs & IPs).
* Capability probing (container vs edge router, presence of traceroute, txtinfo/jsoninfo endpoints) exposed at `/capabilities` for UI feature gating.
* Traceroute helper (if available) and default‑route enrichment with hostname resolution.
* Zero external runtime deps beyond libc + (optionally) `curl` and `ubnt-discover`; everything else is defensive / best‑effort.
* Clean build with strict warnings; internal helpers for safe string assembly & JSON escaping.

For a detailed list of recent changes and upgrade notes please see `CHANGELOG.md`.

Example `/versions.json` snippet (best-effort fields shown):

```json
{
    "host": "edge1",
    "system": "edge-router",
    "olsrd_running": true,
    "olsr2_running": false,
    "bmk_webstatus": "1.3.7",
    "ipv4": "192.168.1.1",
    "ipv6": "fe80::abcd",
    "linkserial": "A4B1C2D3E4F5",
    "olsrd": "OLSRd 0.9.8 - build x86_64",
    "olsrd_details": {
        "version": "0.9.8",
        "description": "OLSRd built for x86_64",
        "device": "EdgeRouter X",
        "date": "2024-05-04",
        "release": "stable",
        "source": "/usr/sbin/olsrd"
    }
}
```


## HTTP Endpoints (JSON unless stated)
| Endpoint | Purpose |
|----------|---------|
| `/` (web UI) | Static SPA assets (Bootstrap, JS) served from `assetroot`.
| `/status` | Full status: system, versions, devices, links, neighbors, routes/topology raw, diagnostics.
| `/status/olsr` | Focused OLSR subset (fast link/neighbor view + default route + flags).
| `/status/lite` | Very fast status (omits heavy OLSR normalization) – good for frequent polling.
| `/devices.json` | Cached UBNT discovery device list (optionally filtered). Supports `?lite=1`.
| `/olsr/links` | Normalized link table (same shape as embedded in `/status`).
| `/olsr/raw` | Concatenated raw JSON from OLSR endpoints (links/routes/topology) for debugging.
| `/olsr/routes?via=IP` | Filtered routes via specific neighbor (or all).
| `/nodedb.json` | Node database map (object keyed by IPv4) – synthesizes if remote/unavailable.
| `/connections.json` | Interface -> (MACs, IPs) mapping derived from ARP.
| `/versions.json` | Plugin + host version snapshot.
| `/capabilities` | Booleans describing environment & optional features.
| `/traceroute.json` (if implemented in UI) | Cached traceroute hops (subset included in `/status`).

Raw OLSR sections optionally embedded in `/status`:
* `olsr_neighbors_raw`
* `olsr_routes_raw`
* `olsr_topology_raw`

### `/devices.json` details

The devices endpoint serves the normalized UBNT discovery results (not ARP synthesis) from the internal discovery cache. Its payload shape is:

```json
{ "devices": [ { "ipv4": "10.0.0.1", "hwaddr": "00:11:22:33:44:55", ... }, ... ], "airos": { /* optional airos info if present */ } }
```

Filtering modes:

* Default (no query parameters):
    * Removes any key whose value is an empty string `""` to reduce bloat.
    * Retains the full remaining set of discovery keys (hostname/product/fwversion/essid/uptime/etc.).
* `?lite=1`:
    * Applies a whitelist of essential keys per object: `ipv4`, `hwaddr`, `hostname`, `product`, `fwversion`, `essid`, `uptime`.
    * Also drops empty-string values like the default mode.

Rationale: the UI only needs a small subset of fields for list rendering; slimming the JSON can significantly reduce bytes transferred when there are many devices. Operators or tooling that require the complete set can continue to use the default (non-lite) form.

Caching: the endpoint participates in the same coalescer / TTL logic as UBNT discovery. A lite response is generated on demand from the cached full array; both forms share the underlying discovery snapshot so calling the lite variant does not trigger additional network probes.

Note: ARP‑derived synthetic devices are intentionally excluded from `/devices.json` even when ARP fallback is enabled globally; the endpoint reflects only concrete discovery replies.

## Data Sources & Normalization Flow
1. Probe local OLSR JSON endpoints (`:9090`, `:2006`, `:8123`) with short timeouts.
2. Concatenate available raw documents for unified parsing.
3. Extract link objects; for each neighbor IP derive:
     * `routes`: count of route entries whose gateway/nextHop matches remote.
     * `nodes`: unique topology destinations reachable via that remote (fallback chain: topology unique -> topology raw count -> two-Hop neighbor count -> routes count -> pattern scan).
4. Resolve default route and flag matching neighbor `is_default`.
5. Enrich LQ/NLQ, cost, reverse DNS, and hostnames.
6. Optionally merge UBNT discovery + ARP into device inventory & node DB.

## Environment & Runtime Detection
* EdgeRouter detection (filesystem layout) to add `admin_url`.
* Container detection (cgroups / proc) to adjust behavior & disable non‑existent hardware probes.
* Presence of tools (`ubnt-discover`, `traceroute`, `curl`).

## Debugging Aids
Set `OLSR_DEBUG_LINK_COUNTS=1` before starting olsrd to emit stderr diagnostics when route/node fallbacks still yield zero.

Controlling DEBUG output
----------------------
A few debug traces are gated and can be enabled at runtime:

- Per-request HTTP debug: enable the plugin parameter `log_request_debug` in your `olsrd.conf` plugin block or set the environment variable `OLSRD_STATUS_LOG_REQUEST_DEBUG=1` (alias `OLSRD_LOG_REQ_DBG=1`) to emit concise per-request debug messages for supported endpoints. Default is `0` (off).
- UBNT discovery debug: set `OLSRD_STATUS_UBNT_DEBUG=1` to enable runtime UBNT discovery tracing (socket, send/recv and TLV parsing). This matches the debug output of the standalone discovery CLI when run with `-d`.

Access logging default and opt-in
--------------------------------
The plugin disables per-request access logging by default to avoid noisy stderr output in normal operation. To enable access logging set one of the following environment variables to a non-zero value:

- Preferred (new): `OLSRD_STATUS_FETCH_LOG_QUEUE=1` — enables fetch/queue and per-request access logging and metrics.
- Legacy/backwards-compatible: `OLSRD_STATUS_ACCESS_LOG=1` — also enables access logging when present.

To explicitly disable access logging (even if an env var exists), set the variable to `0`.

Example (enable access logging):

```bash
export OLSRD_STATUS_FETCH_LOG_QUEUE=1
```


## Build / Install
Build:
```bash
make status_plugin_clean && make status_plugin
sudo make status_plugin_install DESTDIR=/
sudo /usr/share/olsrd-status-plugin/fetch-assets.sh
```

See `docs/ubnt_discover_cli.md` for a small standalone CLI helper that broadcasts a UBNT v1 discovery probe and prints parsed device fields.

## Smoke test: traceroute endpoint

We provide a small smoke test script that verifies the clean traceroute endpoint returns a single JSON object with `trace_target` and `trace_to_uplink` keys.

Run the script (requires curl and jq or python3):

```bash
./scripts/smoke_traceroute.sh <host> <port>
# example (local plugin):
./scripts/smoke_traceroute.sh 127.0.0.1 11080
```

Or run a one-liner using curl + jq:

```bash
curl -sS http://<host>:<port>/status/traceroute | jq .
```

Expected output shape:

```json
{
    "trace_target": "1.2.3.4",
    "trace_to_uplink": [ { "hop": 1, "ip": "1.2.3.4", "host": "example", "ping": "12.345" }, ... ]
}
```

If the endpoint is missing or traceroute is unavailable on the host, the script will print a minimal JSON response or an error; deploy the updated plugin binary and ensure `traceroute` is installed on the host for full results.

Add to olsrd.conf:
```
LoadPlugin "lib/olsrd-status-plugin/build/olsrd_status.so.1.0"
{
    PlParam "bind"       "0.0.0.0"
    PlParam "port"       "11080"
    PlParam "assetroot"  "/usr/share/olsrd-status-plugin/www"
}

## Plugin Parameters
* `bind` – listen address (default 127.0.0.1 if not set).
* `port` – TCP listen port (default 11080 shown above).

* `assetroot` – directory containing `www/` assets (index.html, CSS, JS).

## Environment overrides
The plugin supports a small set of environment variables that can supply runtime defaults or override configuration in specific cases. Use these from systemd unit files, container run commands, or shell wrappers.

Precedence summary
* For `port`, `nodedb_url`, `nodedb_ttl`, and `nodedb_write_disk`: configuration file `PlParam` (olsrd.conf) wins. Environment variables are used only when no `PlParam` is supplied.
* For network allow-list (`Net`): if `OLSRD_STATUS_PLUGIN_NET` is present in the environment it is treated as authoritative and replaces any `PlParam "Net"` entries.

Supported environment variables

* `OLSRD_STATUS_PLUGIN_PORT` – numeric TCP port (1-65535). Example:

```bash
export OLSRD_STATUS_PLUGIN_PORT=8080
```

* `OLSRD_STATUS_PLUGIN_NET` – allow-list entries for HTTP access control. Can contain multiple entries separated by commas, semicolons or whitespace. Each token must be a CIDR (e.g. `192.168.0.0/24`), a single address (`10.0.0.5`) or an address+mask (`192.168.0.0 255.255.252.0`). Example:

```bash
export OLSRD_STATUS_PLUGIN_NET="192.168.1.0/24,10.0.0.0/8"
```

Note: when this env var is present it replaces any `PlParam "Net"` entries from `olsrd.conf`.

* `OLSRD_STATUS_PLUGIN_NODEDB_URL` – URL string for the remote node DB used to populate `nodedb.json`.

```bash
export OLSRD_STATUS_PLUGIN_NODEDB_URL="https://example.com/nodedb.json"

```bash
export OLSRD_STATUS_PLUGIN_NODEDB_TTL=600
```

* `OLSRD_STATUS_PLUGIN_NODEDB_WRITE_DISK` – integer (0 or 1) controlling whether the node DB is written to disk.

```bash
export OLSRD_STATUS_PLUGIN_NODEDB_WRITE_DISK=1
```

* `OLSRD_STATUS_PLUGIN_BIND` – bind address for the HTTP server (IPv4 or IPv6 address string). Example:

```bash
export OLSRD_STATUS_PLUGIN_BIND="0.0.0.0"
```

* `OLSRD_STATUS_PLUGIN_ENABLEIPV6` – integer (0 or 1) to enable IPv6 support. Example:

```bash
export OLSRD_STATUS_PLUGIN_ENABLEIPV6=1
```

* `OLSRD_STATUS_PLUGIN_ASSETROOT` – path to the directory containing static web assets. Example:

```bash
export OLSRD_STATUS_PLUGIN_ASSETROOT="/usr/share/olsrd-status-plugin/www"
```

* `OLSRD_STATUS_FETCH_STARTUP_WAIT` – optional integer seconds to wait during plugin startup for DNS/network readiness before attempting the first remote fetch. Useful in containers where networking may be delayed. Default is 30 seconds.

```bash
export OLSRD_STATUS_FETCH_STARTUP_WAIT=60
```

Additional runtime tuning (PlParam names available in `olsrd.conf` plugin block):
* `OLSRD_STATUS_FETCH_QUEUE_MAX` / PlParam `fetch_queue_max` – maximum number of pending fetch requests queued before new non-waiting requests are dropped. Default: 4.
```bash
export OLSRD_STATUS_FETCH_QUEUE_MAX=8
```
* `log_request_debug` (PlParam) / `OLSRD_STATUS_LOG_REQUEST_DEBUG` or short alias `OLSRD_LOG_REQ_DBG` (env) – optional toggle (0/1) to emit concise per-request debug messages for some endpoints (useful to trace UI fetches like `/status/stats`). Default: 0 (off).
Example (env):

```bash
export OLSRD_LOG_REQ_DBG=1
```

* `OLSRD_STATUS_FETCH_RETRIES` / PlParam `fetch_retries` – number of retry attempts the background fetch worker will make on transient failures. Default: 3.

```bash
export OLSRD_STATUS_FETCH_RETRIES=5
```

Discovery tuning (PlParam names available in `olsrd.conf` plugin block):

* `OLSRD_STATUS_DISCOVER_INTERVAL` / PlParam `discover_interval` – automatic devices discovery interval in seconds. Default: 300s. Valid range: 5 - 86400 (1 day).

export OLSRD_STATUS_DISCOVER_INTERVAL=300
```

* `OLSRD_STATUS_UBNT_PROBE_WINDOW_MS` / PlParam `ubnt_probe_window_ms` – per‑interface UBNT probe collection window in milliseconds (the discover probe is retransmitted at about half this window, min 100ms). Default: 1000 ms. Valid range: 100 - 60000.

```bash
```

* `OLSRD_STATUS_UBNT_SELECT_TIMEOUT_CAP_MS` / PlParam `ubnt_select_timeout_cap_ms` – cap (milliseconds) applied to the select() timeout used during UBNT discovery socket waits. This limits per-iteration sleep to avoid long blocking when adaptive timeouts are calculated; useful to reduce worst-case latency in discovery loops. Default: 100 ms. Valid range: 1 - 10000.

```bash
export OLSRD_STATUS_UBNT_SELECT_TIMEOUT_CAP_MS=200
```

Example `olsrd.conf` plugin block (pasteable):

```
LoadPlugin "lib/olsrd-status-plugin/build/olsrd_status.so.1.0"
{
    PlParam "port"       "11080"
    PlParam "assetroot"  "/usr/share/olsrd-status-plugin/www"
    # Discovery tuning (PlParam wins over environment variables)
    PlParam "discover_interval" "300"            # seconds
    PlParam "ubnt_probe_window_ms" "1000"       # milliseconds
}

# Example: tune the UBNT discovery select timeout cap
# You can set the cap (in milliseconds) so the discovery loop will not block
# longer than this value on select() calls. PlParam in olsrd.conf takes
# precedence over the environment variable.
LoadPlugin "lib/olsrd-status-plugin/build/olsrd_status.so.1.0"
{
    PlParam "port" "11080"
    PlParam "assetroot" "/usr/share/olsrd-status-plugin/www"
    PlParam "discover_interval" "300"
    PlParam "ubnt_probe_window_ms" "1000"
    # Set select timeout cap to 200ms (valid range: 1-10000)
    PlParam "ubnt_select_timeout_cap_ms" "200"
}
```

* `OLSRD_STATUS_FETCH_BACKOFF_INITIAL` / PlParam `fetch_backoff_initial` – initial backoff in seconds used when retrying; backoff doubles each attempt. Default: 1.

```bash
export OLSRD_STATUS_FETCH_BACKOFF_INITIAL=2
```

Precedence: for all of the above the plugin parameter `PlParam` in `olsrd.conf` wins when present; otherwise the corresponding environment variable is used; otherwise the compiled default applies.

### Discovery / devices specific tuning

* `OLSRD_STATUS_UBNT_CACHE_TTL_S` / PlParam `ubnt_cache_ttl_s` – TTL (seconds) for the normalized UBNT discovery cache. Default: 300.
* `OLSRD_STATUS_DISCOVER_INTERVAL` / PlParam `discover_interval` – (already documented above) controls how often a new active discovery cycle runs.
* `OLSRD_STATUS_ALLOW_ARP_FALLBACK` / PlParam `allow_arp_fallback` – when set to `1` allows ARP‑synthesized devices in broader status aggregations (not `/devices.json`). Default: 0.
* `OLSRD_STATUS_ARP_CACHE_TTL_S` / PlParam `arp_cache_ttl_s` – TTL (seconds) for the internal ARP JSON cache used when ARP fallback is enabled. Default: 5.
* `OLSRD_STATUS_STATUS_DEVICES_MODE` / PlParam `status_devices_mode` – controls whether `/status` embeds the (potentially large) devices array: `0` omit devices, `1` include full list (default), `2` include only summary counts.
* `OLSRD_STATUS_COALESCE_DEVICES_TTL` / PlParam `coalesce_devices_ttl` – TTL (seconds) for coalescing `/devices.json` responses. Default: 30.
* `OLSRD_STATUS_COALESCE_DISCOVER_TTL` / PlParam `coalesce_discover_ttl` – TTL (seconds) for coalescing discovery operations. Default: 30.
* `OLSRD_STATUS_COALESCE_TRACEROUTE_TTL` / PlParam `coalesce_traceroute_ttl` – TTL (seconds) for coalescing traceroute operations. Default: 30.

These parameters let you tune payload size and refresh behavior independently: for example you can keep a short ARP cache TTL for fresher MAC/IP correlation while keeping a longer UBNT discovery TTL when device metadata changes rarely.

Logging and debugging

* The plugin logs which environment values are applied or ignored during startup to stderr.

Debug options

The project supports a small set of runtime environment variables and a few build-time switches you can use to enable verbose debug output for specific subsystems. These are intended for development, troubleshooting, and CI; prefer toggling them from systemd unit files or container run commands rather than embedding them in production configs.

Runtime environment variables (examples)

- `OLSR_DEBUG_LINK_COUNTS=1`
    - Emit extra diagnostics during OLSR link/route/node fallback calculations to help explain why neighbor `routes`/`nodes` counts are zero or unexpectedly low.

- `OLSR_DEBUG_ALLOWLIST=1`
    - Verbose allow-list tracing: prints per-entry add/match traces when the plugin computes the final network allow-list (useful when debugging access control tokens via `OLSRD_STATUS_PLUGIN_NET`).

- `OLSRD_STATUS_UBNT_DEBUG=1`
    - Enable runtime UBNT discovery debug output in `rev/discover/ubnt_discover.c` and helpers. This causes the discovery helpers to emit socket, send/recv, and TLV parsing traces to stderr.
    - The standalone CLI also exposes `-d` to set this env var for a single run: `./rev/discover/ubnt_discover_cli -d`.

- `OLSR_STATUS_LOG_REQ_DBG` / `OLSRD_STATUS_LOG_REQUEST_DEBUG` (or short alias `OLSRD_LOG_REQ_DBG=1`)
    - Turn on concise per-request debug messages for HTTP endpoints that support request-level diagnostics (helps trace UI fetches and queued fetch behavior).

- `OLSRD_STATUS_FETCH_LOG_QUEUE` (0/1)
    - Toggle detailed fetch-queue progress messages printed to stderr. Useful to quiet noisy logs or to enable detailed queue traces.

- `OLSRD_STATUS_FETCH_REPORT_INTERVAL` (seconds)
    - When set >0 the plugin emits a short periodic summary of fetch metrics (queue length, dropped, retries) every N seconds.

- `OLSRD_STATUS_ALLOW_ARP_FALLBACK` (0/1)
    - Default: `0` (OFF). When set to `1` the plugin will allow synthesis of device entries from the local ARP table and may include those ARP-derived entries in aggregate status payloads when the code-paths opt-in to ARP fallback (for example the full `/status` output can include ARP-derived devices when enabled).
    - Important: some discovery-specific endpoints intentionally exclude ARP-derived entries to avoid polluting discovery responses. Notably `/discover/ubnt` and `/devices` will not include ARP-synthesized devices regardless of this flag. Use this toggle when you explicitly want ARP-derived supplemental entries in aggregated status views.

Enabling these in systemd (example)

```
Environment=OLSRD_STATUS_UBNT_DEBUG=1 OLSR_DEBUG_ALLOWLIST=1
```

Build-time / compile-time debug

- `UBNT_DEBUG` (compile-time macro)
    - The UBNT discovery sources have a compile-time guard `#ifndef UBNT_DEBUG` which defaults to `0`. To enable extra debug traces from the discovery implementation at build time compile with `-DUBNT_DEBUG=1` added to `CFLAGS` for the plugin or the CLI. Example:

```
make CFLAGS="$(CFLAGS) -DUBNT_DEBUG=1" ubnt_discover_cli
```

Notes & recommendations

- Prefer the runtime env vars for short-lived diagnostics; use build-time macros only when you need extremely verbose traces that are otherwise filtered by `#if` guards.
- The discovery CLI (`rev/discover/ubnt_discover_cli`) is standalone and exposes `-d` to set `OLSRD_STATUS_UBNT_DEBUG` for convenience; use that when iterating quickly.
- When opening issues, include which debug env vars you enabled and a copy of the stderr output to help maintainers reproduce the problem.

Sample stderr snippets

Below are short representative snippets you may see when enabling the corresponding debug option. They are intentionally short — real output will contain timing and socket-specific values.

- `OLSRD_STATUS_UBNT_DEBUG=1` / `-d` on CLI

```
ubnt: opened socket fd=5 bound to 0.0.0.0:10001 (requested local=(any))
ubnt: sent probe via fd=5 to 255.255.255.255:10001
UBNT reply from 192.168.1.2, 42 bytes (parsed):
  parsed tag hwaddr = 00:11:22:33:44:55
  parsed tag ipv4 = 192.168.1.2
  parsed tag product = EdgeRouter X
```

- `OLSR_DEBUG_ALLOWLIST=1`

```
allowlist: parsing token "192.168.1.0/24" -> added
allowlist: checking 10.0.0.5 -> DENIED
allowlist: final allowlist contains 2 entries
```

- `OLSR_DEBUG_LINK_COUNTS=1`

```
linkcounts: neighbor 10.0.0.1 routes=0 topology=2 twohop=1 -> using topology=2
linkcounts: neighbor 10.0.0.2 routes=3 topology=0 twohop=0 -> using routes=3
```

- `OLSRD_STATUS_FETCH_REPORT_INTERVAL` (periodic summary)

```
fetch-report: queue=2 in-flight=1 retries=5 dropped=0 success=12
```

Troubleshooting checklist

1) Missing TLV fields (no hostname/product/fw in discovery replies)
    - Enable: `OLSRD_STATUS_UBNT_DEBUG=1` or `./rev/discover/ubnt_discover_cli -d`
    - Check: stderr for `parsed tag` lines or `UBNT reply` hexdump; if hexdump shows no known tags the device probably doesn't include TLV metadata.

2) Discovery returns only ARP-derived MAC/IP pairs
    - Enable: `OLSRD_STATUS_UBNT_DEBUG=1`
    - Check: look for hexdump and parser messages. ARP fallback is expected when replies lack TLV metadata.

3) UI shows zero `routes` or `nodes` counts for neighbors
    - Enable: `OLSR_DEBUG_LINK_COUNTS=1`
    - Check: which fallback path was used (routes -> topology -> two-hop -> pattern scan) and inspect source documents.

4) Remote `nodedb.json` not being fetched or frequent retries
    - Enable: `OLSRD_STATUS_FETCH_LOG_QUEUE=1` and set `OLSRD_STATUS_FETCH_REPORT_INTERVAL=10`
    - Check: periodic fetch-report and fetch-queue logs; verify network access and `OLSRD_STATUS_PLUGIN_NODEDB_URL`.

5) Requests unexpectedly denied by allow-list
    - Enable: `OLSR_DEBUG_ALLOWLIST=1`
    - Check: per-entry allowlist traces to see which token matched and why the client IP was denied.




### Versions / Info source behavior

The `/versions.json` payload and the UI `Versions` tab synthesize information from multiple sources (local system, container metadata, and data reported by upstream devices such as EdgeRouter firmware). The UI will try to present the most specific and useful fields available:

- `kernel` / `kernel_version` / `os_kernel` — used to display the kernel version in the Versions panel. The renderer will try a few common keys so the UI works across EdgeRouter, Linux container, and standard host reports.
- `olsrd_details` (preferred) — when present this object supplies detailed OLSRd build metadata: `version`, `description`, `device`, `date`, `release`, and `source`.
- Top-level olsr fields — when `olsrd_details` is missing the UI falls back to top-level fields such as `olsrd`, `olsrd_release`, `olsrd_build_date`, or `olsrd_source` when available.

To help operators understand where a given versions snapshot originated, the UI displays an "Info source" entry which indicates whether the values were gathered locally, reported by an EdgeRouter, or derived from container metadata.

This behavior is best-effort and non-fatal: missing fields will be shown as `-` in the UI rather than causing errors. If you rely on a specific field name in automation, prefer the documented top-level keys listed above or query `/status` which embeds the same information.

## Security Notes
* Endpoint intentionally unauthenticated for embedded deployment simplicity; place behind firewall or restrict `bind` to management network if needed.
* All parsing is defensive with bounds checks; malformed upstream JSON will degrade gracefully (empty arrays / zero counts) rather than crash.

## Recent local changes (developer notes)

The local tree includes a few recent, small developer-focused improvements you may find useful when testing or extending the UI:

- Combined diagnostics endpoint: `/diagnostics.json` now aggregates the small set of diagnostic endpoints into one JSON blob with top-level keys: `versions`, `capabilities`, `fetch_debug`, and `summary`. This reduces client-side parallel requests and simplifies the diagnostics drawer logic in the SPA.

- Frontend wiring: the Web UI (`www/js/app.js`) now prefers `/diagnostics.json` for the diagnostics drawer and falls back to the original endpoints (`/versions.json`, `/capabilities`, `/fetch_debug`, `/status/summary`) when the combined endpoint is unavailable.

- Smoke test: a tiny Node smoke-test script has been added at `www/test/diagnostics-smoke.js`. It launches a small local server serving a sample `/diagnostics.json` payload and validates the expected top-level keys. Run it with:

```bash
node www/test/diagnostics-smoke.js
```

- Compiler warning fix: a minor -Wpointer-bool-conversion warning (about using an array identifier in a boolean context) was fixed in `src/olsrd_status_plugin.c` by introducing a small local `const char *dbgmsg` variable before formatting JSON. This silences the warning across compilers without changing runtime behavior.

These changes are intentionally small and non-invasive. If you want the smoke test wired into the existing test scripts (`www/test/package.json`), or prefer the diagnostics endpoint to include additional fields (platform, nodedb summary, etc.), I can add those as a follow-up.

New: versions_string
---------------------
The plugin now emits a small additional field inside the `versions` JSON object called `versions_string`. This is a compact timestamp created at request-time using the format `YYYYMMDDHHMMSS` (date + hours + minutes + seconds). It is included in `/versions.json` and therefore also available in the combined `/diagnostics.json` payload and shown in the Diagnostics drawer of the web UI.

## Extending
Typical extension points inside `src/olsrd_status_plugin.c`:
* Add new counters in `normalize_olsrd_links()`.
* Add alternative discovery sources in `ubnt_discover_output()` or ARP synthesizer.
* Register new HTTP handlers near end of file where existing routes are registered.

## Extensions
This project has a few small runtime extensions you can use for monitoring and to control noisy log output.

- Prometheus metrics endpoint: the plugin exposes a minimal Prometheus-compatible metrics page at `/metrics` which exports fetch queue and counter metrics (queue length, dropped, retries, successes and per-type enqueue/processed counters). Useful for scraping with Prometheus or Promtail.

- Toggle queue-operation logging: suppress detailed fetch-queue progress messages that are printed to stderr by default. Use either the PlParam or environment variable:
    - PlParam: `fetch_log_queue` (0 = off, 1 = on)
    - Env var: `OLSRD_STATUS_FETCH_LOG_QUEUE` (export before starting olsrd)

    Note: the default was changed to be quiet by default in recent updates (the code now initializes `fetch_log_queue` to `0`). To re-enable the per-request "picked request" lines use the PlParam or environment variable above. If you need temporary verbose logs without changing `olsrd.conf`, set `OLSRD_STATUS_FETCH_LOG_FORCE=1` (or PlParam `fetch_log_force`) which forces logging ON regardless of `fetch_log_queue`.

- Periodic fetch reporter: a periodic summary of fetch metrics can be enabled via PlParam `fetch_report_interval` or env `OLSRD_STATUS_FETCH_REPORT_INTERVAL` (seconds). When enabled this prints a short summary to stderr every N seconds; it respects the `fetch_log_queue` toggle.

- UI auto-refresh hint: the plugin can suggest an auto-refresh interval to the web UI via PlParam `fetch_auto_refresh_ms` or env `OLSRD_STATUS_FETCH_AUTO_REFRESH_MS` (milliseconds). The front-end honors this as a suggested default for the Fetch Queue auto-refresh control.

Examples

```bash
# disable fetch queue log noise entirely
export OLSRD_STATUS_FETCH_LOG_QUEUE=0

# enable periodic summary every 60s
export OLSRD_STATUS_FETCH_REPORT_INTERVAL=60
```

These extensions are intentionally lightweight so they can be toggled from systemd unit files or container env without changing `olsrd.conf`.

## License
Same license as upstream olsrd project (inherit; add explicit file header if distributing separately).

---
This README summarizes functionality; for deeper internals inspect `src/olsrd_status_plugin.c` (single translation unit for easier embedding) and the `www/js/app.js` UI logic.

## Build-time fetch options

Two Makefile options control how the plugin fetches remote resources (notably `nodedb.json`):

- `ENABLE_CURL_FALLBACK` (default: `1`) — when enabled, if libcurl is not available the plugin will attempt to spawn an external `curl` binary at runtime as a last resort. Set to `0` to disable the external-binary fallback and require libcurl or accept no HTTPS fetching.

    Example: build without external fallback:

    ```bash
    make ENABLE_CURL_FALLBACK=0
    ```

- `REQUIRE_FETCH` (default: `0`) — opt-in hard failure when neither libcurl (dev headers detected at build) nor an external `curl` binary are present. This is useful for CI or production images where missing fetch capability should abort the build early.

    Example: fail build if no fetch capability is present:

    ```bash
    make REQUIRE_FETCH=1
    ```

During `make` you will see diagnostic messages such as:

```
>>> libcurl NOT detected; building without libcurl support
>>> external curl fallback: ENABLED (set ENABLE_CURL_FALLBACK=0 to disable)
```

Runtime expectations

* If libcurl dev headers were available at build time, the binary will use libcurl for HTTPS fetches (recommended).
* If libcurl wasn't available but `ENABLE_CURL_FALLBACK=1`, the plugin will attempt to spawn an external `curl` binary when needed — ensure `curl` is installed in the runtime image.
* If libcurl wasn't available and `ENABLE_CURL_FALLBACK=0`, the plugin will not attempt external fetches; remote HTTPS node DB fetching will not occur (plain http:// URLs may still work via the internal socket helper).

Recommendations:

* For production builds, install libcurl dev packages in the build image so the plugin includes native HTTPS fetching.
* For minimal runtime images, either ensure `curl` binary is present or keep `ENABLE_CURL_FALLBACK=1` and accept the external dependency.

```

# how to bring it into the build env
scp olsrd.......zip ubnt@172.30.1.96:/home/ubnt/

# from the root of your olsrd repo
unzip -o olsrd-status-plugin-packed-v11.zip -d .

# build the plugin
make -C lib/olsrd-status-plugin status_plugin_clean status_plugin

# install the .so and helper files
sudo make -C lib/olsrd-status-plugin status_plugin_install DESTDIR=/

# fetch Bootstrap + glyphicons to the assetroot
sudo /usr/share/olsrd-status-plugin/fetch-assets.sh


# how to load plugin
LoadPlugin "lib/olsrd-status-plugin/build/olsrd_status.so.1.0"
{
    PlParam "bind"       "0.0.0.0"
    PlParam "port"       "11080"
    PlParam "enableipv6" "0"
    PlParam "assetroot"  "/usr/share/olsrd-status-plugin/www"
}
