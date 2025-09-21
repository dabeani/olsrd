/* Collectors to read OLSR internal tables directly and write textual output
 * into a struct autobuf. Intended for in-process use by olsrd-status-plugin
 * to avoid TCP/IPC calls to txtinfo/jsoninfo.
 */

#ifndef OLSRD_STATUS_COLLECTORS_H
#define OLSRD_STATUS_COLLECTORS_H

#include "common/autobuf.h"

void status_collect_neighbors(struct autobuf *ab);
void status_collect_links(struct autobuf *ab);
void status_collect_routes(struct autobuf *ab);
void status_collect_topology(struct autobuf *ab);
void status_collect_hna(struct autobuf *ab);
void status_collect_mid(struct autobuf *ab);

#endif /* OLSRD_STATUS_COLLECTORS_H */
