#include "ubnt_discover.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>

int main(int argc, char *argv[]) {
    printf("UBNT Discovery Packet Capture Tool\n");
    printf("Set OLSRD_STATUS_UBNT_DEBUG=1 to enable hexdumps\n");
    printf("Press Ctrl+C to exit\n\n");

    int sock = ubnt_open_broadcast_socket(0);
    if (sock < 0) {
        fprintf(stderr, "Failed to create broadcast socket\n");
        return 1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(10001);
    dst.sin_addr.s_addr = htonl(INADDR_BROADCAST);

    printf("Sending UBNT discovery probe...\n");
    if (ubnt_discover_send(sock, &dst) < 0) {
        fprintf(stderr, "Failed to send probe\n");
        close(sock);
        return 1;
    }

    printf("Listening for responses (timeout: 5 seconds)...\n");

    fd_set rfds;
    struct timeval tv;
    int max_fd = sock + 1;

    while (1) {
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        int ret = select(max_fd, &rfds, NULL, NULL, &tv);
        if (ret < 0) {
            perror("select");
            break;
        } else if (ret == 0) {
            printf("Timeout - no more responses\n");
            break;
        }

        if (FD_ISSET(sock, &rfds)) {
            struct ubnt_kv kv[32];
            size_t kvn = sizeof(kv)/sizeof(kv[0]);
            char ip[64] = {0};
            int n = ubnt_discover_recv(sock, ip, sizeof(ip), kv, &kvn);

            if (n > 0) {
                printf("\n=== Response from %s (%d bytes) ===\n", ip, n);
                for (size_t i = 0; i < kvn; i++) {
                    printf("%s = %s\n", kv[i].key, kv[i].value);
                }
                if (kvn == 0) {
                    printf("(No known TLVs parsed - enable OLSRD_STATUS_UBNT_DEBUG=1 for hexdump)\n");
                }
            }
        }
    }

    close(sock);
    return 0;
}