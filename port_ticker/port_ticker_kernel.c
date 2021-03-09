/*
 * port_ticker_kernel.c
 *
 * [/csh:]> date "+%D"
 * 03/09/21
 *
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

/* The VLAN tag header is not exported by any of the IP header files */
struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

/* port connection queue map
 * BPF_MAP_TYPE_LRU_HASH: Each hash maintains an LRU (least recently used)
 * list for each bucket to inform delete when the hash bucket fills up.
 * Note: a bpf map has about a 4GB size limitation */
struct bpf_map_def SEC("maps") queue_map = { //map 0
	.type        = BPF_MAP_TYPE_LRU_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct conn_queue_t),
	.max_entries = MAXQ_ENTRIES,
};

/* This is our reporting map used in userspace. Store ip addresses when
 * dest_port changes exceed threshold */
struct bpf_map_def SEC("maps") report_map = { //map 1
	.type        = BPF_MAP_TYPE_LRU_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct ipaddr_info_t),
	.max_entries = MAXADDR_ENTRIES,
};

/* ignore ip list */
struct bpf_map_def SEC("maps") ignore_map = { //map 2
	.type        = BPF_MAP_TYPE_LRU_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct ignore_addr_t),
	.max_entries = MAXIGNORE_ENTRIES,
};

/* icmp, threshold settings  */
struct bpf_map_def SEC("maps") ctrl_map = { //map 3
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct ctrl_settings_t),
	.max_entries = 1, /* just a single entry is all thats needed */
};

/* Destination port */
static __always_inline int chk_ipv4(void *data, __u64 nh_off, void *data_end) {
	struct iphdr *iph = data + nh_off;
	struct tcphdr *tcph;
	struct udphdr *udph;
	struct conn_queue_t *cq_data;
	struct ctrl_settings_t *s_data;
	struct ignore_addr_t *i_data;
	int hl_len;
	__be32 src_ip;
	__be32 dest_ip;
	__u32  dest_port = 0;
        __u32  s_key = 0;

	/* verifier boundary check, drop invalid ip header */
	if(iph + 1 > data_end) {
		return -1;
	}

	src_ip  = iph->saddr;
	dest_ip = iph->daddr;

	/* ignore src ip address? */
	i_data =  bpf_map_lookup_elem(&ignore_map, &src_ip);
	if(i_data) {
		if(i_data->ignore == 1) {
			#if DEBUG_FLAG
			bpf_printk("[DEBUG]: IGNORE src_ip:%u",src_ip);
			#endif
			return 0;
		}
	}

	#if DROP_BOGAS
	/* DROP these src_ip, dest_ip */
	if((src_ip == dest_ip) || src_ip == 0 || dest_ip == 0 || dest_ip == 0xffffffff) { /* 255.255.255.255 */
		return -1;
	}
	#endif

	/* variable-length TCP header validity check */
	hl_len = iph->ihl * 4;
	if(iph->tot_len < (ETH_HLEN + nh_off + hl_len)) {
		return -1;
	}

	//bpf_printk("[DEBUG]: src_ip:%u dest_ip:%u dest_port:%u",dest_ip(src_ip),bpf_ntohl(dest_ip),dest_port);

	/* grab settings */
	s_data = bpf_map_lookup_elem(&ctrl_map, &s_key);
	if(!s_data) {
		#if DEBUG_FLAG
		bpf_printk("[DEBUG]: Control settings data not found!");
		#endif
		return -1;
	}

	/* ICMP */
	if(iph->protocol == IPPROTO_ICMP) {
		struct icmphdr *icmph;
		icmph = data + nh_off + hl_len;

		if(icmph + 1 > data_end) {
			return -1;
		}

		/* DROP ICMP ? */
		if(s_data->enable_icmp == 0) {
			#if DEBUG_FLAG
			bpf_printk("[DEBUG]: Dropping ICMP packet");
			#endif
			return -1; /* DROP ? */
		}

		return 0;

	} else if(iph->protocol == IPPROTO_TCP) {
		tcph = data + nh_off + hl_len;

		#if 0
		/* if we want to check the tcp flags, one way to do it
		 * see: netinet/tcp.h */
		/* calculate fin:syn:rst:psh:ack:urg:ece:cwr */
		__u16 th_flags = 0;
		th_flags += (tcph->fin << 0);
		th_flags += (tcph->syn << 1);
		th_flags += (tcph->rst << 2);
		th_flags += (tcph->psh << 3);
		th_flags += (tcph->ack << 4);
		th_flags += (tcph->urg << 5);
		th_flags += (tcph->ece << 6);
		th_flags += (tcph->cwr << 7);
		if(th_flags == (TH_SYN | TH_PUSH | TH_URG)) {
			// do something ...
		}
		#endif

		/* verifier boundary check */
		if(tcph + 1 > data_end) {
			return -1;
		}

		/* verifier boundary check */
		if(!tcph->dest) {
			return -1;
		}

		dest_port = bpf_ntohs(tcph->dest);

		//#if DEBUG_FLAG
		//bpf_printk("[DEBUG]: IPPROTO_TCP src_ip key:%u dest_port:%u",src_ip,dest_port);
		//#endif

	} else if(iph->protocol == IPPROTO_UDP) {
		udph = data + nh_off + hl_len;

		/* verifier boundary check */
		if(udph + 1 > data_end) {
			return -1;
		}

		/* verifier boundary check */
		if(!udph->dest) {
			return -1;
		}

		dest_port = bpf_ntohs(udph->dest);

		//#if DEBUG_FLAG
		//bpf_printk("[DEBUG]: IPPROTO_UDP src_ip key:%u dest_port:%u",src_ip,dest_port);
		//#endif

	} else {
		//#if DEBUG_FLAG
		//bpf_printk("[DEBUG]: chk_ipv4 HIT default rule!");
		//#endif
		return 0;
	}

	cq_data = bpf_map_lookup_elem(&queue_map, &src_ip);
	if(cq_data) {
		if(cq_data->last_port != dest_port) {
			struct conn_queue_t val;
			val.last_port  = dest_port;
			val.change_cnt = (cq_data->change_cnt + 1);
			bpf_map_update_elem(&queue_map, &src_ip, &val, BPF_EXIST);

		   	//bpf_printk("[DEBUG]: PORT CHANGE DETECTED - src_ip:%u new_port:%u change_count:%u",src_ip,dest_port, cq_data->change_cnt);

			/* update reporting map */
			if(val.change_cnt > s_data->threshold) {
				struct ipaddr_info_t report_data;
				report_data.change_cnt = val.change_cnt;
				bpf_map_update_elem(&report_map, &src_ip, &report_data, BPF_ANY);

				#if DEBUG_FLAG
		   		bpf_printk("[DEBUG]: PORT CHANGE > THRESHOLD - src_ip:%u threshold:%u change_count:%u",src_ip,s_data->threshold,cq_data->change_cnt);
				#endif
			}
		}

	} else {
		struct conn_queue_t val;
		val.last_port  = dest_port;
		val.change_cnt = 0;
		bpf_map_update_elem(&queue_map, &src_ip, &val, BPF_ANY);
	}

	return 0;
}

SEC("pticker")
int pticker_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	int ret;
	__u64 nh_off;	/* initial network header offset */
	__u16 h_proto;	/* packet proto type ID (IPv4,IPv6,ARP, etc..) */
	__u32 rc = XDP_DROP; /* default action */

	/* verifier boundary check, just drop invalid packets */
	nh_off = sizeof(*eth);
	if(data + nh_off > data_end) {
		return rc;
	}

	h_proto = eth->h_proto;
	nh_off  = sizeof(*eth);

	/*
	 * - Make adjustments for any vlan tagged frames
	 * - Make use of bpf_ntohs() and bpf_htons() functions to convert to and from host byte order, respectively.
	 *   See the comment at the top of ../libbpf/src/bpf_endian.h */
        if(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);

		/* verifier boundary check */
		if(data + nh_off > data_end) {
			return rc;
		}

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}
	/* one more time for double vlan tagging */
	if(h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vhdr;

		vhdr = data + nh_off;
		nh_off += sizeof(struct vlan_hdr);

		/* verifier boundary check */
		if(data + nh_off > data_end) {
			return rc;
		}

		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	/* allow ARP packets */
	if(h_proto == bpf_htons(ETH_P_ARP)) {
		return XDP_PASS;

	/* IPv4 packets */
	} else if(h_proto == bpf_htons(ETH_P_IP)) {

		/* ipv4 port scan check */
		ret = chk_ipv4(data, nh_off, data_end);
		if(ret == -1) {
			return rc;
		}

	/* IPv6 packets */
	} else if(h_proto == bpf_htons(ETH_P_IPV6)) {
		return XDP_PASS;
	}


	//#if DEBUG_FLAG
	//bpf_printk("[DEBUG]: XDP_PASS [OK]");
	//#endif
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

