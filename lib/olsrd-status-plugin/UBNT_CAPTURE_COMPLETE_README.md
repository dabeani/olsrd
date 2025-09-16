# UBNT Discovery Packet Capture and Testing Guide

This guide provides comprehensive instructions for capturing UBNT discovery packets from routers and integrating them into the test suite for the OLSR status plugin.

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Capture Methods](#capture-methods)
- [Tools and Scripts](#tools-and-scripts)
- [Adding Test Cases](#adding-test-cases)
- [Advanced Usage](#advanced-usage)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)

## Overview

The UBNT discovery system in the OLSR status plugin can parse discovery packets from various Ubiquiti devices (EdgeRouter, UniFi, AirFiber, etc.). To improve parser coverage and test edge cases, you can capture real packets from your network and add them to the test suite.

The system supports:
- **TLV parsing** for known packet formats
- **Fallback parsing** for unknown formats
- **Debug hexdumps** for unparsed packets
- **Comprehensive test suite** with real captured data

## Quick Start

1. **Build the capture tools:**
   ```bash
   cd /Users/bernhard/olsrd-status-plugin/olsrd-status-plugin
   gcc -Irev/discover -o ubnt_capture ubnt_capture.c rev/discover/ubnt_discover.c
   chmod +x capture_ubnt.sh format_hex.py
   ```

2. **Capture packets:**
   ```bash
   export OLSRD_STATUS_UBNT_DEBUG=1
   ./capture_ubnt.sh
   ```

3. **Format and test:**
   ```bash
   python3 format_hex.py ubnt_dump_*.txt
   gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out
   ```

## Capture Methods

### Method 1: Automated Capture Script (Recommended)

The `capture_ubnt.sh` script provides the easiest way to capture packets:

```bash
# Basic capture
./capture_ubnt.sh

# Capture on specific interface
./capture_ubnt.sh eth0

# Save to custom file
./capture_ubnt.sh eth0 my_capture.txt
```

**Features:**
- Automatic probe sending
- 5-second response timeout
- Debug hexdump output
- Timestamped log files
- Human-readable summaries

### Method 2: Standalone Capture Tool

Use `ubnt_capture` for manual control:

```bash
# Enable hexdumps for unparsed packets
export OLSRD_STATUS_UBNT_DEBUG=1

# Run capture
./ubnt_capture

# Output shows:
# - Probe sending confirmation
# - Response summaries with parsed fields
# - Hexdumps for unparsed packets
```

### Method 3: OLSR Plugin Integration

Capture packets through the running OLSR plugin:

```bash
# Enable debug logging
export OLSRD_STATUS_UBNT_DEBUG=1

# Start OLSRD with status plugin
# Visit: http://localhost:8080/discover/ubnt

# Check stderr logs for hexdumps of unparsed packets
tail -f /var/log/olsrd.log | grep -A 20 "UBNT reply"
```

### Method 4: Network Sniffing

Use standard network tools for complete capture:

```bash
# Real-time capture with tcpdump
sudo tcpdump -i eth0 -n udp port 10001 -X

# Save to PCAP file
sudo tcpdump -i eth0 -n udp port 10001 -w ubnt_packets.pcap

# Analyze with Wireshark
wireshark ubnt_packets.pcap
```

### Method 5: Custom Integration

For embedded systems or custom applications:

```c
#include "rev/discover/ubnt_discover.h"

// Create broadcast socket
int sock = ubnt_open_broadcast_socket(0);

// Send probe
struct sockaddr_in dst = {/* broadcast address */};
ubnt_discover_send(sock, &dst);

// Receive responses
struct ubnt_kv kv[32];
size_t kvn = 32;
char ip[64];
int bytes = ubnt_discover_recv(sock, ip, sizeof(ip), kv, &kvn);
```

## Tools and Scripts

### capture_ubnt.sh
**Purpose:** Automated packet capture with logging
**Usage:** `./capture_ubnt.sh [interface] [output_file]`
**Features:**
- Sends UBNT discovery probe
- Listens for responses
- Saves timestamped logs
- Enables debug output

### ubnt_capture.c / ubnt_capture
**Purpose:** Standalone capture tool
**Usage:** `./ubnt_capture`
**Features:**
- Manual probe sending
- Real-time response display
- Parsed field output
- Debug hexdump support

### format_hex.py
**Purpose:** Convert hexdump to C array format
**Usage:** `python3 format_hex.py <input_file>`
**Features:**
- Parses hexdump output
- Generates C array syntax
- Ready for test suite integration

### Built-in Test Suite
**Location:** `rev/discover/ubnt_discover.c` (UBNT_DISCOVER_TEST)
**Usage:**
```bash
gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c
./a.out
```

## Adding Test Cases

### Step 1: Capture Packets

Use any capture method above to get packet data. Look for output like:

```
UBNT reply from 192.168.1.100, 256 bytes (unparsed):
0000  01 00 01 53 02 00 0a 44 d9 e7 50 37 b0 4e 29 76
0010  45 02 00 0a 44 d9 e7 50 37 b0 4e 29 76 45 02 00
...
```

### Step 2: Format the Data

```bash
# Use the formatter script
python3 format_hex.py ubnt_dump_20231201_143022.txt
```

Output:
```c
/* UBNT discovery response dump */
const uint8_t buf[] = {
    0x01,0x00,0x01,0x53,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,
    0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,
    // ... more bytes ...
};
size_t len = sizeof(buf); /* 256 bytes */
```

### Step 3: Add to Test Suite

Edit `rev/discover/ubnt_discover.c` and replace the test data:

```c
#ifdef UBNT_DISCOVER_TEST
int main(void) {
    struct ubnt_kv kv[32]; size_t cap = 32; size_t filled = cap;
    /* Replace with your captured data */
    const uint8_t buf[] = {
        0x01,0x00,0x01,0x53,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,
        // ... your captured bytes ...
    };
    size_t len = sizeof(buf);
    size_t out = parse_tlv(buf, len, kv, filled);
    // ... rest of test code ...
}
#endif
```

### Step 4: Test and Validate

```bash
# Compile and run test
gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out

# Check output for parsed fields
# If no fields parsed, the hexdump will show - this is expected for new formats
```

## Advanced Usage

### Environment Variables

- `OLSRD_STATUS_UBNT_DEBUG=1`: Enable hexdumps for unparsed packets
- `OLSRD_STATUS_UBNT_DEBUG=y`: Same as above
- `OLSRD_STATUS_UBNT_DEBUG=Y`: Same as above

### Custom Socket Binding

For multi-interface systems:

```c
// Bind to specific interface
int sock = ubnt_open_broadcast_socket_bound("192.168.1.10", 0);

// Or use system calls
int sock = socket(AF_INET, SOCK_DGRAM, 0);
int broadcast = 1;
setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast));
// bind to specific interface...
```

### Timeout Control

Modify timeouts in capture tools:

```c
// In ubnt_capture.c
tv.tv_sec = 10;  // 10 second timeout
tv.tv_usec = 0;
```

### Multiple Responses

The capture tools handle multiple simultaneous responses:

```
=== Response from 192.168.1.100 (256 bytes) ===
hostname = ubnt-router-1
...

=== Response from 192.168.1.101 (256 bytes) ===
hostname = ubnt-router-2
...
```

## Troubleshooting

### No Responses Received

**Problem:** Capture shows "Timeout - no more responses"

**Solutions:**
- Check network connectivity to UBNT devices
- Ensure devices are on the same broadcast domain
- Try different network interfaces
- Verify firewall rules allow UDP port 10001
- Use `sudo` if permission denied

### No Hexdumps Appearing

**Problem:** Packets received but no hexdump output

**Solutions:**
- Set `export OLSRD_STATUS_UBNT_DEBUG=1`
- Check that packets are actually unparsed (parsed packets don't dump)
- Verify stderr output destination

### Permission Errors

**Problem:** "Permission denied" or socket errors

**Solutions:**
- Use `sudo` for raw socket access
- Check interface permissions
- Try different network interfaces

### Parse Failures

**Problem:** Packets captured but parsing fails

**Solutions:**
- This is expected for new/unknown packet formats
- The hexdump is still valuable for analysis
- Consider adding new TLV parsers for unknown tags

### Compilation Errors

**Problem:** GCC fails to compile capture tools

**Solutions:**
- Ensure correct include paths: `-Irev/discover`
- Check for missing dependencies
- Verify all source files are present

## Examples

### Complete Capture Session

```bash
# Setup
cd /Users/bernhard/olsrd-status-plugin/olsrd-status-plugin
export OLSRD_STATUS_UBNT_DEBUG=1

# Capture
./capture_ubnt.sh eth0 edge_router_dump.txt

# Format
python3 format_hex.py edge_router_dump.txt > edge_router.hex

# Test
gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out
```

### Integration Test Output

```
UBNT Discovery Packet Capture
=============================
Interface: eth0
Output: edge_router_dump.txt

Starting capture (press Ctrl+C to stop)...
Sending UBNT discovery probe...
Listening for responses (timeout: 5 seconds)...

=== Response from 192.168.1.100 (256 bytes) ===
hostname = EdgeRouter-X
product = EdgeRouter X 5-Port
firmware = EdgeOS v2.0.9-hotfix.1
uptime = 259200

0000  01 00 01 53 02 00 0a 44 d9 e7 50 37 b0 4e 29 76
0010  45 02 00 0a 44 d9 e7 50 37 b0 4e 29 76 45 02 00
...
```

### Test Suite Results

```
parse_tlv returned 4 entries
hostname=EdgeRouter-X
product=EdgeRouter X 5-Port
firmware=EdgeOS v2.0.9-hotfix.1
uptime=259200
```

## Contributing

When adding new test cases:

1. **Document the device:** Include model, firmware version, and capture conditions
2. **Test edge cases:** Capture from various network conditions
3. **Validate parsing:** Ensure new TLV tags are properly handled
4. **Update documentation:** Add examples to this guide

## Files Reference

- `capture_ubnt.sh` - Automated capture script
- `ubnt_capture.c` - Standalone capture tool source
- `format_hex.py` - Hexdump to C array converter
- `rev/discover/ubnt_discover.c` - Main discovery code and test suite
- `UBNT_CAPTURE_README.md` - This documentation

---

**Last Updated:** September 13, 2025
**Plugin Version:** OLSR Status Plugin with UBNT Discovery</content>
<parameter name="filePath">/Users/bernhard/olsrd-status-plugin/olsrd-status-plugin/UBNT_CAPTURE_COMPLETE_README.md