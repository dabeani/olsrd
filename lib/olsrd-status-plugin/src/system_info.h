/* System information collection utilities header */

#ifndef SYSTEM_INFO_H
#define SYSTEM_INFO_H

void get_system_hostname(char *hostname, size_t len);
void get_primary_ipv4(char *ipaddr, size_t len);
long get_system_uptime_seconds(void);
void get_default_ipv4_route(char *ip, size_t ip_len, char *dev, size_t dev_len);
void get_default_ipv6_route(char *ip, size_t ip_len, char *dev, size_t dev_len);

#endif /* SYSTEM_INFO_H */