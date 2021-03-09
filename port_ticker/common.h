#pragma once
#ifndef COMMON_H
#define COMMON_H 1

/* debug */
#define DEBUG_FLAG	1

/* DROP_BOGAS, if enabled will drop the following packets
 *   - if src or dest ip = 0.0.0.0 (aka: 0)
 *   - if dest ip = 255.255.255.255
 *   - if src ip == dest ip */
#define DROP_BOGAS	  0

/* map's max entries keep in mind the more entires the more memory is used
 * a single bpf map has about a 4GB max size limitation */
#define MAXQ_ENTRIES	  120	/* max map queue entries */
#define MAXADDR_ENTRIES	  100	/* max reporting entries (read by userspace program) */
#define MAXIGNORE_ENTRIES 10	/* max ignored ip entries */

/* src_ip:dest_port change queue
 * todo: track pps maybe? */
struct conn_queue_t {
	__u32 change_cnt; /* number of times port changed from last_port */
	__u32 last_port;  /* last recorded port ip_addr used */
};

/* src ip address log, used for userspace reporting  */
struct ipaddr_info_t {
	__u32 ip_addr; /* src ip */
	__u32 change_cnt; /* port changed count */
};

/* control settings */
struct ctrl_settings_t {
	__u32 threshold;   /* port change threshold */
	__u32 enable_icmp; /* enable/disable icmp */
};

/* ip addr ignore map data */
struct ignore_addr_t {
	__u32 ignore;
};

#endif /* COMMON_H */
