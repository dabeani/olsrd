#pragma once
/*
 * Minimal UBNT discovery v1 client (UDP/10001).
 *
 * This is a clean-room, best-effort reimplementation that sends the common
 * 4-byte v1 probe and parses replies as generic TLVs when possible.
 * It is designed to be embedded in a C plugin (e.g., olsrd status plugin).
 *
 * API:
 *   - ubnt_discover_send(int sock, const struct sockaddr_in *dst)
 *   - ubnt_discover_recv(int sock, char *ip, size_t iplen, struct ubnt_kv *kv, size_t *kvcount)
 *
 * Notes:
 *   - Replies vary across device lines/firmware. We parse TLV conservatively and
 *     also surface raw payload for debugging if needed.
 *   - Known UDP port: 10001. Broadcast address: 255.255.255.255
 */
#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Simple key/value structure for parsed fields */
struct ubnt_kv {
    char key[32];
    char value[128];
};

/* Send a v1 probe to dst (UDP/10001). Returns 0 on success, -1 on error. */
int ubnt_discover_send(int sock, const struct sockaddr_in *dst);

/* Receive a reply. On success, fills sender IP string and up to *kvcount entries.
 * On entry, *kvcount is the capacity of kv[]. On return, it's the number filled.
 * Returns number of bytes received (>=0), or -1 on error / timeout.
 */
int ubnt_discover_recv(int sock, char *ip, size_t iplen, struct ubnt_kv *kv, size_t *kvcount);

/* Utility: configure a UDP socket for broadcast and bind to INADDR_ANY:0.
 * Returns socket fd >=0 or -1 on error.
 */
int ubnt_open_broadcast_socket(uint16_t port_bind);

/* Bind a UDP socket to a specific local IPv4 address and port for per-interface
 * broadcast probing. Returns socket fd >=0 or -1 on error.
 */
int ubnt_open_broadcast_socket_bound(const char *local_ipv4, uint16_t port_bind);

/* Utility: hex dump (for debugging) */
void ubnt_hexdump(const void *buf, size_t len);

#ifdef __cplusplus
}
#endif
