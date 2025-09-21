## Quick orientation for AI coding agents

This repo is the OLSRd routing daemon and its plugins. Focus: C code, a top-level daemon in `src/`, and many plugins in `lib/` (each plugin in `lib/<name>/`). The `lib/olsrd-status-plugin` is a representative, relatively large plugin with HTTP endpoints, JSON normalization and many repo conventions.

Key places to read first
- `Makefile` (top-level): orchestrates builds, `libs` target, and plugin build loop.
- `src/` : core daemon sources and `lq_plugin*` for link-quality hooks.
- `lib/` : plugins; each plugin has its own `Makefile` and `build/` outputs.
- `lib/olsrd-status-plugin/README.md` and `lib/olsrd-status-plugin/src/olsrd_status_plugin.c` — canonical examples of environment variables, PlParam precedence, endpoints and normalization patterns.

Big-picture architecture notes
- Core daemon: `src/` produces `olsrd` executable. Plugins are dynamically loaded shared objects under `lib/*/build/` (e.g. `lib/olsrd-status-plugin/build/olsrd_status.so.1.0`).
- Plugins expose small, self-contained features and use the olsrd plugin API (`olsrd_plugin.h`). They frequently implement background workers, a simple HTTP server, or OLSR JSON proxying.
- Data flow in status plugin: probe OLSR JSON endpoints (ports like 9090/2006/8123), normalize (parse/merge) into internal JSON shapes, enrich with device discovery (UBNT), ARP fallbacks and emit HTTP JSON endpoints listed in the plugin README.

Developer workflows (concrete commands)
- Build everything: `make` (top-level). Build plugins only: `make libs`.
- Build only status plugin (from repo root): `make -C lib/olsrd-status-plugin` or in plugin dir `make status_plugin` / `make status_plugin_install`.
- Clean & rebuild plugin: `make status_plugin_clean && make status_plugin`.
- Install plugin assets (after install): `sudo /usr/share/olsrd-status-plugin/fetch-assets.sh` (see plugin README).
- Cross-build helpers: `build_armv5.sh`, `cp_arm*.sh`, and `do_*.sh` in `docker/` — use these for embedded targets.

Project-specific conventions and patterns
- Configuration precedence: PlParam in `olsrd.conf` wins > environment variables `OLSRD_STATUS_*` > compiled defaults. See `lib/olsrd-status-plugin/README.md` for exact env var names (e.g. `OLSRD_STATUS_PLUGIN_PORT`, `OLSRD_STATUS_UBNT_DEBUG`).
- Plugins keep static defaults at top of C files (example: `g_asset_root` in `olsrd_status_plugin.c`). Look for `getenv()` calls and `PlParam` parsing for runtime config.
- Naming: plugin build outputs follow `olsrd_*` prefix and are loaded via `LoadPlugin "lib/<plugin>/build/olsrd_*"` blocks in `olsrd.conf` (search repo for `LoadPlugin`).
- Many plugins prefer minimal runtime deps; prefer defensive code (timeouts, short probes) and best-effort fallbacks (ARP, cached snapshots).

Integration points & external dependencies
- OLSRd JSON/status endpoints (probed by plugins): ports like 9090, 2006, 8123 — handlers in plugin source register HTTP paths such as `/status`, `/olsr/links`, `/capabilities`.
- UBNT discovery helper: `rev/discover/ubnt_discover.c` and `rev/discover/ubnt_discover_cli` used by the status plugin for device discovery.
- Optional system tools: `traceroute`, `curl` (used by tests and some helpers).

Where to change behavior safely
- Modify JSON normalization or HTTP handlers in `lib/olsrd-status-plugin/src/olsrd_status_plugin.c` — look for `h_olsrd_json`, `h_capabilities_local`, `normalize_olsrd_links` and related symbols.
- Add or tune PlParams by adjusting plugin parsing code and documenting the new name in the plugin README.
- For global behaviour, change `src/` or `Makefile.inc` only when you understand cross-platform conditions (see `Makefile` OS checks like `ifeq ($(OS),linux)`).

Small actionable examples
- To add an HTTP endpoint in the status plugin: register handler in the plugin's init function and implement `static int h_new(http_request_t *r)` alongside existing handlers referenced near `h_olsrd_json` in `olsrd_status_plugin.c`.
- To enable verbose UBNT debug at runtime: set `export OLSRD_STATUS_UBNT_DEBUG=1` before starting olsrd or call the discovery CLI with `-d`.
- To reproduce a failing normalization case: run the plugin against a local OLSRd JSON endpoint and fetch `/status/raw` (or use `curl http://127.0.0.1:11080/olsr/raw`).

Notes to an AI agent
- Prefer small, local changes and add tests or a smoke script when changing normalization logic. The repo contains small smoke helpers (e.g. `scripts/smoke_traceroute.sh`) — reuse them.
- Keep the project's strict-warning posture (many Makefiles enable warnings); avoid adding global dependencies unless necessary.
- When updating docs or config names, update `lib/*/README.md` for the affected plugin and the top-level `files/olsrd.conf.default.lq` example if PlParam names are user-facing.

If anything here is unclear or you'd like the file to include more examples (init function location, common http handler signatures, or a short grep list of symbols to edit), tell me which area to expand.
