#!/bin/bash
# UBNT Discovery Packet Capture Script
# Usage: ./capture_ubnt.sh [interface] [output_file]

INTERFACE=${1:-""}
OUTPUT_FILE=${2:-"ubnt_dump_$(date +%Y%m%d_%H%M%S).txt"}

echo "UBNT Discovery Packet Capture"
echo "============================="
echo "Interface: ${INTERFACE:-auto}"
echo "Output: $OUTPUT_FILE"
echo ""

# Set debug environment variable for hexdumps
export OLSRD_STATUS_UBNT_DEBUG=1

echo "Starting capture (press Ctrl+C to stop)..."
echo "Raw packet data will be saved to $OUTPUT_FILE"
echo ""

# Run the capture tool
if [ -n "$INTERFACE" ]; then
    # If interface specified, you might need to bind to it
    echo "Note: For specific interface, ensure the socket binds to that interface's IP"
fi

./ubnt_capture 2>&1 | tee "$OUTPUT_FILE"

echo ""
echo "Capture complete. Raw data saved to $OUTPUT_FILE"
echo ""
echo "To add this dump to the test suite:"
echo "1. Extract the hex bytes from the hexdump in $OUTPUT_FILE"
echo "2. Add them to the UBNT_DISCOVER_TEST array in ubnt_discover.c"
echo "3. Test with: gcc -DUBNT_DISCOVER_TEST rev/discover/ubnt_discover.c && ./a.out"