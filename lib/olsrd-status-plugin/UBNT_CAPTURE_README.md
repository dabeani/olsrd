# UBNT Discovery Packet Capture Guide

This guide explains how to capture UBNT discovery packets from routers and add them to the test suite.

## Quick Start

1. **Compile the capture tool:**
   ```bash
   make clean && make  # Build the main plugin
   gcc -Irev/discover -o ubnt_capture ubnt_capture.c rev/discover/ubnt_discover.c
   ```

2. **Run the capture script:**
   ```bash
   ./capture_ubnt.sh
   ```
   This will:
   - Send a UBNT discovery probe
   - Listen for responses (5 second timeout)
   - Save raw hexdump to `ubnt_dump_YYYYMMDD_HHMMSS.txt`

3. **Format the captured data:**
   ```bash
   python3 format_hex.py ubnt_dump_YYYYMMDD_HHMMSS.txt
   ```

## Manual Capture Methods

### Method 1: Using the Plugin (Production)
The OLSR status plugin automatically captures packets when accessing `/discover/ubnt`:

```bash
# Enable debug logging
export OLSRD_STATUS_UBNT_DEBUG=1

# Start OLSRD with the plugin
# Then access: http://localhost:8080/discover/ubnt

# Check OLSRD logs for hexdumps of unparsed packets
```

### Method 2: Standalone Capture Tool
Use the provided `ubnt_capture` tool:

```bash
# Enable hexdumps
export OLSRD_STATUS_UBNT_DEBUG=1

# Run capture
./ubnt_capture
```

### Method 3: Network Sniffing
Use tcpdump/wireshark to capture UDP port 10001:

```bash
# Capture UBNT discovery traffic
sudo tcpdump -i <interface> -n udp port 10001 -X

# Or save to file for later analysis
sudo tcpdump -i <interface> -n udp port 10001 -w ubnt_capture.pcap
```

## Adding New Test Cases

1. **Capture a packet dump** using any method above
2. **Extract the hex bytes** from the hexdump output
3. **Add to test suite** in `rev/discover/ubnt_discover.c`:

```c
#ifdef UBNT_DISCOVER_TEST
/* Test harness using your captured hex dump */
int main(void) {
    const uint8_t buf[] = {
        0x01,0x00,0x01,0x53,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,
        // ... your captured bytes here ...
    };
    // ... rest of test code ...
}
#endif
```

4. **Test the new case:**
```bash
gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out
```

## Tips for Good Captures

- **Multiple devices:** Capture from networks with different UBNT device models
- **Different firmware:** Try various firmware versions for the same model
- **Error cases:** Capture packets that fail to parse (enable `OLSRD_STATUS_UBNT_DEBUG=1`)
- **Network conditions:** Test with different network topologies and interference levels

## Troubleshooting

- **No responses:** Ensure routers are on the same broadcast domain
- **Permission denied:** Run with sudo for raw socket access if needed
- **No hexdump:** Set `OLSRD_STATUS_UBNT_DEBUG=1` environment variable
- **Parse failures:** Look for unknown TLV tags that need to be added to the parser

## Example Output

```
UBNT Discovery Packet Capture
=============================
Interface: auto
Output: ubnt_dump_20231201_143022.txt

Starting capture (press Ctrl+C to stop)...
Sending UBNT discovery probe...
Listening for responses (timeout: 5 seconds)...

=== Response from 192.168.1.100 (256 bytes) ===
hostname = ubnt-router
product = EdgeRouter X
firmware = EdgeOS v2.0.9
uptime = 123456

0000  01 00 01 53 02 00 0a 44 d9 e7 50 37 b0 4e 29 76
0010  45 02 00 0a 44 d9 e7 50 37 b0 4e 29 76 45 02 00
...
```

The hex dump can then be formatted and added to the test suite.