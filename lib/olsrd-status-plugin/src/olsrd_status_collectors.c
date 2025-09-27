/* Collectors adapted from lib/txtinfo to generate the same textual tables
 * directly from OLSRd in-memory tables. Kept local to the plugin so no
 * dependency on other plugins is required.
 */

#include "olsrd_status_collectors.h"

#include <unistd.h>

#include "neighbor_table.h"
#include "mpr_selector_set.h"
#include "mid_set.h"
#include "routing_table.h"
#include "lq_plugin.h"
#include "hna_set.h"
#include "tc_set.h"
#include "link_set.h"

/* Neighbors (simplified: no vtime / 2hop listing) */
static void ipc_print_neighbors_internal(struct autobuf *abuf, bool list_2hop) {
  struct ipaddr_str neighAddrBuf;
  struct neighbor_entry *neigh;
  struct neighbor_2_list_entry *list_2;
  int thop_cnt;

  const char * field;
  if (list_2hop) {
    field = "(2-hop address)+";
  } else {
    field = "2-hop count";
  }

  abuf_puts(abuf, "Table: Neighbors\n");
  abuf_appendf(abuf, "IP address\tSYM\tMPR\tMPRS\tWill.\t%s\n", field);

  OLSR_FOR_ALL_NBR_ENTRIES(neigh) {
    abuf_appendf(abuf, "%s\t%s\t%s\t%s\t%d",
      olsr_ip_to_string(&neighAddrBuf, &neigh->neighbor_main_addr),
      (neigh->status == SYM) ? "YES" : "NO",
      neigh->is_mpr ? "YES" : "NO",
      olsr_lookup_mprs_set(&neigh->neighbor_main_addr) ? "YES" : "NO",
      neigh->willingness);
    thop_cnt = 0;

    for (list_2 = neigh->neighbor_2_list.next; list_2 != &neigh->neighbor_2_list; list_2 = list_2->next) {
      if (list_2hop) {
        if (list_2->neighbor_2) {
          abuf_appendf(abuf, "\t%s", olsr_ip_to_string(&neighAddrBuf, &list_2->neighbor_2->neighbor_2_addr));
        }
      } else {
        thop_cnt++;
      }
    }

    if (!list_2hop) {
      abuf_appendf(abuf, "\t%d", thop_cnt);
    }
    abuf_puts(abuf, "\n");
  } OLSR_FOR_ALL_NBR_ENTRIES_END(neigh);
  abuf_puts(abuf, "\n");
}

void status_collect_neighbors(struct autobuf *ab) {
  ipc_print_neighbors_internal(ab, false);
}

/* Links */
void status_collect_links(struct autobuf *abuf) {
  struct link_entry *my_link;
  abuf_puts(abuf, "Table: Links\n");
  abuf_puts(abuf, "Local IP\tRemote IP\tHyst.\tLQ\tNLQ\tCost\tInterface\n");

  OLSR_FOR_ALL_LINK_ENTRIES(my_link) {
    struct ipaddr_str localAddr;
    struct ipaddr_str remoteAddr;
    struct lqtextbuffer lqbuffer;
    struct lqtextbuffer costbuffer;

    abuf_appendf(abuf, "%s\t%s\t%u.%03u\t%s\t%s\t%s\n",
      olsr_ip_to_string(&localAddr, &my_link->local_iface_addr),
      olsr_ip_to_string(&remoteAddr, &my_link->neighbor_iface_addr),
      0, 0,
      get_link_entry_text(my_link, '\t', &lqbuffer),
      get_linkcost_text(my_link->linkcost, false, &costbuffer),
      my_link->if_name ? my_link->if_name : "");
  } OLSR_FOR_ALL_LINK_ENTRIES_END(my_link);
  abuf_puts(abuf, "\n");
}

/* Routes */
void status_collect_routes(struct autobuf *abuf) {
  struct rt_entry *rt;
  abuf_puts(abuf, "Table: Routes\n");
  abuf_puts(abuf, "Destination\tGateway IP\tMetric\tETX\tInterface\n");

  OLSR_FOR_ALL_RT_ENTRIES(rt) {
    struct ipaddr_str dstAddr;
    struct ipaddr_str nexthopAddr;
    struct lqtextbuffer costbuffer;

    if (rt->rt_best) {
      /* Append a small JSON fragment at end of line so fallback parsers can detect gateway/destination keys */
      abuf_appendf(abuf, "%s/%d\t%s\t%d\t%s\t%s\t{\"destination\":\"%s/%d\",\"gateway\":\"%s\"}\n",
        olsr_ip_to_string(&dstAddr, &rt->rt_dst.prefix),
        rt->rt_dst.prefix_len,
        olsr_ip_to_string(&nexthopAddr, &rt->rt_best->rtp_nexthop.gateway),
        rt->rt_best->rtp_metric.hops,
        get_linkcost_text(rt->rt_best->rtp_metric.cost, true, &costbuffer),
        if_ifwithindex_name(rt->rt_best->rtp_nexthop.iif_index),
        olsr_ip_to_string(&dstAddr, &rt->rt_dst.prefix), rt->rt_dst.prefix_len,
        olsr_ip_to_string(&nexthopAddr, &rt->rt_best->rtp_nexthop.gateway));
    }
  } OLSR_FOR_ALL_RT_ENTRIES_END(rt);
  abuf_puts(abuf, "\n");
}

/* Topology */
void status_collect_topology(struct autobuf *abuf) {
  struct tc_entry *tc;
  abuf_puts(abuf, "Table: Topology\n");
  abuf_puts(abuf, "Dest. IP\tLast hop IP\tLQ\tNLQ\tCost\n");

  OLSR_FOR_ALL_TC_ENTRIES(tc) {
    struct tc_edge_entry *tc_edge;
    OLSR_FOR_ALL_TC_EDGE_ENTRIES(tc, tc_edge) {
      if (tc_edge->edge_inv) {
        struct ipaddr_str dstAddr;
        struct ipaddr_str lastHopAddr;
        struct lqtextbuffer lqbuffer;
        struct lqtextbuffer costbuffer;

        /* Append tiny JSON object with destination and lastHop to help fallback scanners */
        abuf_appendf(abuf, "%s\t%s\t%s\t%s\t{\"destinationIP\":\"%s\",\"lastHopIP\":\"%s\"}\n",
          olsr_ip_to_string(&dstAddr, &tc_edge->T_dest_addr),
          olsr_ip_to_string(&lastHopAddr, &tc->addr),
          get_tc_edge_entry_text(tc_edge, '\t', &lqbuffer),
          get_linkcost_text(tc_edge->cost, false, &costbuffer),
          olsr_ip_to_string(&dstAddr, &tc_edge->T_dest_addr),
          olsr_ip_to_string(&lastHopAddr, &tc->addr));
      }
    } OLSR_FOR_ALL_TC_EDGE_ENTRIES_END(tc, tc_edge);
  } OLSR_FOR_ALL_TC_ENTRIES_END(tc);
  abuf_puts(abuf, "\n");
}

/* HNA */
void status_collect_hna(struct autobuf *abuf) {
  struct ip_prefix_list *hna;
  struct hna_entry *tmp_hna;
  struct ipaddr_str prefixbuf;
  struct ipaddr_str gwaddrbuf;

  abuf_puts(abuf, "Table: HNA\n");
  abuf_puts(abuf, "Destination\tGateway\n");

  /* Announced HNA entries from configuration */
  if (olsr_cnf && olsr_cnf->hna_entries) {
    for (hna = olsr_cnf->hna_entries; hna != NULL ; hna = hna->next) {
      abuf_appendf(abuf, "%s/%d\t%s\n",
        olsr_ip_to_string(&prefixbuf, &hna->net.prefix),
        hna->net.prefix_len,
        olsr_ip_to_string(&gwaddrbuf, &olsr_cnf->main_addr));
    }
  }

  /* HNA entries in the HNA set */
  OLSR_FOR_ALL_HNA_ENTRIES(tmp_hna) {
    struct hna_net *tmp_net;
    for (tmp_net = tmp_hna->networks.next; tmp_net != &tmp_hna->networks; tmp_net = tmp_net->next) {
      abuf_appendf(abuf, "%s/%d\t%s\n",
        olsr_ip_to_string(&prefixbuf, &tmp_net->hna_prefix.prefix),
        tmp_net->hna_prefix.prefix_len,
        olsr_ip_to_string(&gwaddrbuf, &tmp_hna->A_gateway_addr));
    }
  } OLSR_FOR_ALL_HNA_ENTRIES_END(tmp_hna);
  abuf_puts(abuf, "\n");
}

/* MID */
void status_collect_mid(struct autobuf *abuf) {
  int idx;
  abuf_puts(abuf, "Table: MID\n");
  abuf_puts(abuf, "IP address\t(Alias)+\n");

  for (idx = 0; idx < HASHSIZE; idx++) {
    struct mid_entry *entry = mid_set[idx].next;
    while (entry && (entry != &mid_set[idx])) {
      struct mid_address *alias = entry->aliases;
      struct ipaddr_str ipAddr;

      abuf_puts(abuf, olsr_ip_to_string(&ipAddr, &entry->main_addr));
      abuf_puts(abuf, "\t");

      while (alias) {
        struct ipaddr_str buf2;
        abuf_appendf(abuf, "\t%s", olsr_ip_to_string(&buf2, &alias->alias));
        alias = alias->next;
      }

      abuf_puts(abuf, "\n");
      entry = entry->next;
    }
  }
  abuf_puts(abuf, "\n");
}
