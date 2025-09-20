#define _POSIX_C_SOURCE 200112L
#include "ubnt_discover.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

/* UDP port used by UBNT discovery */
#define UBNT_DISCOVERY_PORT 10001
#define UBNT_MAX_TAG_VALUE 0x41
#define UBNT_MIN_PRINTABLE_RUN 3
#define UBNT_MAX_VALUE_LEN 128
#define UBNT_MAX_KEY_LEN 32

/* The most common v1 probe payload observed in the wild is 4 bytes: 0x01 0x00 0x00 0x00.
 * We send that by default.
 */
static const uint8_t UBNT_V1_PROBE[4] = { 0x01, 0x00, 0x00, 0x00 };

/* Some devices respond with TLV-like blobs. We attempt to parse common tags.
 * These tag IDs are best-effort (community-observed) and may vary by device:
 *   0x01 = MAC(6)
 *   0x02 = IPv4(4)
 *   0x0B = Hostname (string)
 *   0x0C = Product (string)
 *   0x0D = Firmware version (string)
 *   0x2A = ESSID (string)         [may vary]
 *   0x40 = Uptime (u32 seconds)   [may vary]
 *   0x41 = System status (u32)    [may vary]
 * If parsing fails, we still return raw hexdump via stderr for debugging.
 */
struct tlv {
    uint8_t type;
    uint8_t len;
    const uint8_t *val;
};
/* Tag definitions moved to optimized lookup table below */

static const char *tag_name(uint8_t t, int *is_str, int *is_ipv4, int *is_mac, int *is_u32) {
    /* Optimized lookup table for fast tag resolution */
    static const struct tag_info {
        const char *name;
        int is_str, is_ipv4, is_mac, is_u32;
    } TAG_LOOKUP[0x42] = {
        [0x01] = {"hwaddr", 0, 0, 1, 0},
        [0x02] = {"ipv4",   0, 1, 0, 0},
        [0x0B] = {"hostname", 1, 0, 0, 0},
        [0x0C] = {"product", 1, 0, 0, 0},
        [0x0D] = {"fwversion",1, 0, 0, 0},
        [0x2A] = {"essid",    1, 0, 0, 0},
        [0x40] = {"uptime",   0, 0, 0, 1},
        [0x41] = {"system_status",0,0,0,1},
    };

    if (t < sizeof(TAG_LOOKUP)/sizeof(TAG_LOOKUP[0]) && TAG_LOOKUP[t].name) {
        if (is_str) *is_str = TAG_LOOKUP[t].is_str;
        if (is_ipv4) *is_ipv4 = TAG_LOOKUP[t].is_ipv4;
        if (is_mac) *is_mac = TAG_LOOKUP[t].is_mac;
        if (is_u32) *is_u32 = TAG_LOOKUP[t].is_u32;
        return TAG_LOOKUP[t].name;
    }
    if (is_str) *is_str = 0;
    if (is_ipv4) *is_ipv4 = 0;
    if (is_mac) *is_mac = 0;
    if (is_u32) *is_u32 = 0;
    return NULL;
}

/* helper removed (previously used to validate printable TLV strings) */

void ubnt_hexdump(const void *buf, size_t len) {
    /* Only emit hexdump when UBNT debug is explicitly enabled via env */
    int dbg = 0;
    const char *e = getenv("OLSRD_STATUS_UBNT_DEBUG");
    if (e && (*e=='1' || *e=='y' || *e=='Y')) dbg = 1;
    if (!dbg) return;

    const unsigned char *p = (const unsigned char*)buf;
    for (size_t i=0;i<len;i+=16) {
        fprintf(stderr, "%04zx  ", i);
        for (size_t j=0;j<16;j++) {
            if (i+j < len) fprintf(stderr, "%02x ", p[i+j]);
            else fprintf(stderr, "   ");
        }
        fprintf(stderr, " ");
        for (size_t j=0;j<16 && i+j<len;j++) {
            unsigned char c = p[i+j];
            fputc(isprint(c) ? c : '.', stderr);
        }
        fputc('\n', stderr);
    }
}

int ubnt_open_broadcast_socket(uint16_t port_bind) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port_bind);

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        // Not fatal for discovery; allow ephemeral port bind by retrying with 0
        addr.sin_port = htons(0);
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(s);
            return -1;
        }
    }

    // non-blocking for nicer integration
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    return s;
}

int ubnt_open_broadcast_socket_bound(const char *local_ipv4, uint16_t port_bind) {
    if (!local_ipv4) return -1;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    int on = 1;
    setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port_bind);
    if (inet_pton(AF_INET, local_ipv4, &addr.sin_addr) != 1) {
        close(s); return -1;
    }
    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        /* try ephemeral port fallback */
        addr.sin_port = htons(0);
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) { close(s); return -1; }
    }
    /* non-blocking */
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
    return s;
}

int ubnt_discover_send(int sock, const struct sockaddr_in *dst) {
    if (!dst) return -1;
    ssize_t n = sendto(sock, UBNT_V1_PROBE, sizeof(UBNT_V1_PROBE), 0,
                       (const struct sockaddr*)dst, sizeof(*dst));
    return (n == (ssize_t)sizeof(UBNT_V1_PROBE)) ? 0 : -1;
}

static size_t kv_put(struct ubnt_kv *kv, size_t cap, size_t idx, const char *k, const char *v) {
    if (idx >= cap) return idx;
    snprintf(kv[idx].key, sizeof(kv[idx].key), "%s", k);
    snprintf(kv[idx].value, sizeof(kv[idx].value), "%s", v);
    return idx+1;
}

/* Very defensive TLV parser */
static size_t parse_tlv(const uint8_t *buf, size_t len, struct ubnt_kv *kv, size_t cap) {
    size_t i = 0, out = 0;
    while (i + 2 <= len) {
        uint8_t t = buf[i++];
        uint8_t l = buf[i++];
        if (i + l > len) break;
        const uint8_t *v = buf + i;
        int is_str, is_ipv4, is_mac, is_u32;
        const char *name = tag_name(t, &is_str, &is_ipv4, &is_mac, &is_u32);
        if (name) {
            char val[128] = {0};
            if (is_mac && l==6) {
                snprintf(val, sizeof(val), "%02X:%02X:%02X:%02X:%02X:%02X",
                         v[0],v[1],v[2],v[3],v[4],v[5]);
                out = kv_put(kv, cap, out, name, val);
            } else if (is_ipv4 && l==4) {
                char ipbuf[INET_ADDRSTRLEN];
                struct in_addr ia; memcpy(&ia, v, 4);
                snprintf(val, sizeof(val), "%s", inet_ntop(AF_INET, &ia, ipbuf, sizeof(ipbuf)));
                out = kv_put(kv, cap, out, name, val);
            } else if (is_u32 && l==4) {
                // many devices send little-endian fields regardless of CPU endianness
                uint32_t u = (uint32_t)v[0] | ((uint32_t)v[1]<<8) | ((uint32_t)v[2]<<16) | ((uint32_t)v[3]<<24);
                snprintf(val, sizeof(val), "%u", u);
                out = kv_put(kv, cap, out, name, val);
            } else if (is_str && l>0 && l < (int)sizeof(val)) {
                // allow NUL within len
                size_t copy = l;
                memcpy(val, v, copy);
                // strip trailing NULs
                while (copy>0 && val[copy-1]==0) copy--;
                val[copy] = 0;
                // make sure printable
                int ok = 1;
                for (size_t j=0;j<copy;j++) if (!isprint((unsigned char)val[j])) { ok=0; break; }
                if (ok) out = kv_put(kv, cap, out, name, val);
            } else {
                /* Unknown tag: accept printable strings as generic entries.
                 * If the value begins with '{' or '[' treat it as JSON and use key json_<TAG>;
                 * otherwise use str_<TAG> so hostnames/product/version are captured.
                 */
                if (l > 0) {
                    int printable = 1;
                    for (size_t j = 0; j < l; ++j) {
                        unsigned char c = v[j];
                        if (!isprint(c) && c != '\r' && c != '\n' && c != '\t') { printable = 0; break; }
                    }
                    if (printable) {
                        char val2[UBNT_MAX_VALUE_LEN] = {0};
                        size_t copy = l;
                        if (copy >= sizeof(val2)) copy = sizeof(val2) - 1;
                        memcpy(val2, v, copy);
                        while (copy > 0 && val2[copy-1] == 0) copy--;
                        val2[copy] = 0;
                        char keybuf[UBNT_MAX_KEY_LEN];
                        const char *pfx = (v[0] == '{' || v[0] == '[') ? "json" : "str";
                        snprintf(keybuf, sizeof(keybuf), "%s_%02X", pfx, t);
                        out = kv_put(kv, cap, out, keybuf, val2);
                    }
                }
            }
        }
        i += l;
    }
    /* If nothing parsed, as a last resort scan for printable ASCII runs and add them
     * as generic string entries (str_<N>). This helps capture hostnames/product/version
     * embedded in vendor blobs when TLV framing differs.
     */
    if (out == 0 && buf && len > 0 && kv && cap > 0) {
        size_t idx = 0; size_t pos = 0;
        while (pos < len && out < cap) {
            /* find start of printable run */
            while (pos < len && !isprint(buf[pos])) pos++;
            if (pos >= len) break;
            size_t start = pos;
            while (pos < len && isprint(buf[pos])) pos++;
            size_t run = pos - start;
            if (run >= UBNT_MIN_PRINTABLE_RUN) {
                char val[UBNT_MAX_VALUE_LEN] = {0}; size_t copy = (run < sizeof(val)-1) ? run : (sizeof(val)-1);
                memcpy(val, buf+start, copy); val[copy] = 0;
                char keybuf[UBNT_MAX_KEY_LEN]; snprintf(keybuf, sizeof(keybuf), "str_%02zu", ++idx);
                out = kv_put(kv, cap, out, keybuf, val);
            }
        }
    }
    return out;
}

    #ifdef UBNT_DISCOVER_TEST
    /* Test harness using the user's captured hex dump (UBNT reply from 78.41.118.69) */
    int main(void) {
        struct ubnt_kv kv[32]; size_t cap = 32; size_t filled = cap;
        /* captured bytes */
        const uint8_t buf[] = {
            0x01,0x00,0x01,0x53,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,
            0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,
            0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,
            0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,
            0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,
            0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,
            0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,
            0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,
            0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,
            0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,
            0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,
            0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,
            0x50,0x37,0xb0,0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,
            0x4e,0x29,0x76,0x0a,0x1e,0x18,0x64,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,
            0x4e,0x29,0x76,0x45,0x02,0x00,0x0a,0x44,0xd9,0xe7,0x50,0x37,0xb0,0x4e,0x29,0x76,
            0x45,0x01,0x00,0x06,0x44,0xd9,0xe7,0x50,0x37,0xab,0x0a,0x00,0x04,0x00,0x06,0x8e,
            0x53,0x0b,0x00,0x15,0x73,0x69,0x65,0x62,0x65,0x6e,0x68,0x69,0x72,0x74,0x65,0x6e,
            0x31,0x35,0x2d,0x72,0x6f,0x75,0x74,0x65,0x72,0x0c,0x00,0x08,0x45,0x52,0x2d,0x58,
            0x2d,0x53,0x46,0x50,0x03,0x00,0x2c,0x45,0x64,0x67,0x65,0x52,0x6f,0x75,0x74,0x65,
            0x72,0x2e,0x45,0x52,0x2d,0x65,0x35,0x30,0x2e,0x76,0x33,0x2e,0x30,0x2e,0x30,0x2e,
            0x35,0x38,0x34,0x32,0x37,0x38,0x37,0x2e,0x32,0x35,0x30,0x37,0x31,0x38,0x2e,0x31,
            0x30,0x35,0x38,0x18,0x00,0x04,0x00,0x00,0x00,0x00
        };
        size_t len = sizeof(buf);
        size_t out = parse_tlv(buf, len, kv, filled);
        printf("parse_tlv returned %zu entries\n", out);
        if (out == 0) {
            fprintf(stderr, "no known TLVs parsed; hexdump follows:\n");
            ubnt_hexdump(buf, len);
        } else {
            for (size_t i = 0; i < out; ++i) printf("%s=%s\n", kv[i].key, kv[i].value);
        }
        return 0;
    }
    #endif

int ubnt_discover_recv(int sock, char *ip, size_t iplen, struct ubnt_kv *kv, size_t *kvcount) {
    uint8_t buf[2048];
    struct sockaddr_in src; socklen_t sl = sizeof(src);
    ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&src, &sl);
    if (n < 0) return -1;
    if (ip && iplen) snprintf(ip, iplen, "%s", inet_ntoa(src.sin_addr));
    size_t cap = kvcount ? *kvcount : 0;
    size_t out = 0;
    if (kv && cap) out = parse_tlv(buf, (size_t)n, kv, cap);
    if (kvcount) *kvcount = out;

    /* If nothing parsed, dump raw for debugging only when env debug is set */
    if (out == 0) {
        const char *e = getenv("OLSRD_STATUS_UBNT_DEBUG");
        if (e && (*e=='1' || *e=='y' || *e=='Y')) {
            fprintf(stderr, "UBNT reply from %s, %zd bytes (unparsed):\n", ip?ip:"?", n);
            ubnt_hexdump(buf, (size_t)n);
        }
    }
    return (int)n;
}
