UBNT Capture — Quick Notes

This short note explains how to build the `ubnt_capture` helper and run the `capture_ubnt.sh` script to collect UBNT discovery packets.

Prerequisites
- Unix-like host (Linux/macOS).
- `gcc` and `make` installed.
- `python3` (optional) to format hex dumps.
- Raw socket access (may require `sudo`).

Build the helper

You can build the plugin (and helper) via the plugin Makefile:

```bash
# build plugin (does a full plugin build)
make clean && make
```

Or compile only the helper manually:

```bash
gcc -Irev/discover -o ubnt_capture ubnt_capture.c rev/discover/ubnt_discover.c
```

Run the capture script

```bash
chmod +x capture_ubnt.sh
# Run (may require sudo for raw sockets)
./capture_ubnt.sh
```

What to expect
- The script sends a UBNT discovery probe, listens for replies (short timeout), and writes a hexdump file named like `ubnt_dump_YYYYMMDD_HHMMSS.txt` in this directory.
- Use `python3 format_hex.py <dumpfile>` to produce a formatted hex array suitable for adding to `rev/discover/ubnt_discover.c` test cases.

Quick test harness

To run the unit-style test harness with a captured dump (example):

```bash
gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out
```

Troubleshooting
- Permission denied: re-run with `sudo` to allow raw socket access.
- No responses: ensure target devices are on the same broadcast domain and not blocked by firewall rules.
- Enable debug logging: set `OLSRD_STATUS_UBNT_DEBUG=1` when running the plugin or helper to see hexdumps in logs.

Where to add captures
- Formatted captures can be pasted into `rev/discover/ubnt_discover.c` (see the `UBNT_DISCOVER_TEST` harness) to add new test vectors.
