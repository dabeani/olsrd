# CHANGELOG

All notable changes to this project are recorded in this file.

Unreleased
---------

This release contains a set of refactors, security hardening and UI improvements intended to make the plugin
safer, more portable and easier to operate in both EdgeRouter and container deployments.

- Internalized script logic: the previous `versions.sh` and `connections.sh` calls have been ported into the
  plugin; `/versions.json` and `/connections.json` are now generated internally (no runtime shellscript
  dependencies required).
- Network allow-list: new multi-valued plugin parameter `PlParam "Net" "<CIDR>"` allows restricting the
  embedded webserver to one or more networks (CIDR). Add multiple `PlParam "Net"` lines to permit multiple
  networks.
- Hardening: the HTTP server and utility helpers were tightened (request size limits, HTTP method checks,
  safe string copying, caps on helper outputs for `util_exec`, `util_http_get_url_local`, `util_read_file`,
  and safer JSON assembly/parsing) to reduce risk of buffer overflows and resource exhaustion.
- OLSRd version details: `/versions.json` now includes `olsrd` (short string) and `olsrd_details` (object with
  `version`, `description`, `device`, `date`, `release`, `source`) when available; the Versions tab in the UI
  will display these fields.
- UI polish: Versions tab was modernized to use Bootstrap panels, consistent refresh controls across tabs, and
  added badges/icons for readability.
- Environment-awareness: better detection for EdgeRouter vs Linux container layouts and olsrd watchdog/plugin
  presence; auto-update wizard version aggregation retained and exposed in versions output.

Usage notes:
- If you previously shipped `versions.sh` or `connections.sh` alongside the plugin you no longer need them;
  their functionality is served by the plugin itself.
- To restrict access to the webserver add one or more `PlParam "Net" "<CIDR>"` entries to the plugin block in
  your `olsrd.conf` (for example: `PlParam "Net" "192.168.1.0/24"`).
- Rebuild/install as before (see README Build / Install). After installing, verify `/versions.json` from a
  permitted host to see the new fields.
# Changelog

## [Unreleased]
- feature: Add CIDR-aware node name lookup to resolve destinations via node_db longest-prefix matching (improves node counting in OLSR Links)
- fix: Silence compiler warnings and free temporary gw_stats allocation
- perf: Replace ad-hoc lookups with consistent node_db resolution for both routing-table fan-out and topology parsing
- feature: Add PlParam `log_request_debug` and env var `OLSRD_STATUS_LOG_REQUEST_DEBUG` (alias `OLSRD_LOG_REQ_DBG`) to enable concise per-request debug logging for UI fetch endpoints (default off).
- ui: Redesigned Statistics tab (improved graphs and summaries; removed small 'dot' indicators) - work-in-progress

