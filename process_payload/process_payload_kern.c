/* 
 * process payload data example
 *
 * [/csh:]> date "+%D"
 * 03/11/21  
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

#define PAYLOAD_SZ	32 /* max payload size we want to store */
#define DEST_PORT	80 /* process packets for DEST_PORT */

#define likely(x)	__builtin_expect((x),1)
#define unlikely(x)	__builtin_expect((x),0)

/* The VLAN tag header is not exported by any of the IP header files */
struct vlan_hdr {
	__be16  h_vlan_TCI;
	__be16  h_vlan_encapsulated_proto;
};

struct bpf_map_def SEC("maps") payload_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = (PAYLOAD_SZ * sizeof(char)),
	.max_entries = 1,
};

static __always_inline int parse_packet(struct xdp_md *ctx, void *hdr,  __u8 protocol) {
	void *data_end = (void *)(long)ctx->data_end;
	struct tcphdr *th;
	struct udphdr *uh;
	char *payload, *buf;
	__u32 payload_offset = 0;
	__u32 sport = 0;
	__u32 dport = 0;
	__u32 key = 0;
	__u32 i;

	switch(protocol) {
		case IPPROTO_TCP:
			th = hdr;
			if(th + 1 > data_end) {
				goto out;
			}

			bpf_printk("[DEBUG]: IPPROTO_TCP");
			payload_offset = (th->doff * 4);

                	dport = bpf_ntohs(th->dest);
			sport = bpf_ntohs(th->source);
		break;
		case IPPROTO_UDP:
			uh = hdr;
			if(uh + 1 > data_end) {
				goto out;
			}

			bpf_printk("[DEBUG]: IPPROTO_UDP");
			payload_offset = sizeof(struct udphdr);

			dport = bpf_ntohs(uh->dest);
			sport = bpf_ntohs(uh->source);
		break;
		/* fall through */
		case IPPROTO_ICMP:
		case IPPROTO_ICMPV6:
		default:
			goto out;
	}

	/* skip if not DEST_PORT */
	if(dport != DEST_PORT) {
		goto out;
	}

	/* payload too large?
	 * todo?: explicitly check min,max payload sizes */
	if((hdr + payload_offset + PAYLOAD_SZ) > data_end) {
		//bpf_printk("[DEBUG]: payload_offset:%u error",payload_offset);
		goto out;
        }

	/* note: initialse the map from userspace first
	 * avoid's having to add any addinonal instructions */
	buf = bpf_map_lookup_elem(&payload_map, &key);
	if(!buf) {
		goto out;
	}

	payload = &((char *) hdr)[payload_offset];
	__builtin_memset(buf, 0, PAYLOAD_SZ);

/* bpf doesn't allow looping, let the compiler unroll it */
#pragma clang loop unroll(full)
	for(i = 0; i < PAYLOAD_SZ; ++i) {
		buf[i] = payload[i];
	}

	bpf_printk("[DEBUG]: sport:%u dport:%u",sport,dport);
	bpf_printk("[DEBUG]: payload = %s",buf);

out:
	return XDP_PASS;
}

static __always_inline int parse_eth(struct ethhdr *eth, void *data_end, __u16 *eth_proto, __u64 *l3_offset) {
	__u16 eth_type;
	__u64 offset;

        offset = sizeof(*eth);
	if((void *)eth + offset > data_end) {
		return 0;
	}

	eth_type = eth->h_proto;

	/* Skip non 802.3 Ethertypes */
	if(unlikely(bpf_ntohs(eth_type) < ETH_P_802_3_MIN)) {
		return 0;
	}

	/* Handle VLAN tagged packet */
	if(eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);

		if((void *)eth + offset > data_end) {
			return 0;
		}

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}
        /* Handle double VLAN tagged packet */
	if(eth_type == bpf_htons(ETH_P_8021Q) || eth_type == bpf_htons(ETH_P_8021AD)) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)eth + offset;
		offset += sizeof(*vlan_hdr);

		if((void *)eth + offset > data_end) {
			return 0;
		}

		eth_type = vlan_hdr->h_vlan_encapsulated_proto;
	}

	*eth_proto = bpf_ntohs(eth_type);
	*l3_offset = offset;
	return 1;
}

static __always_inline int do_ipv4(struct xdp_md *ctx, __u64 nh_off) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct iphdr *ip4h = data + nh_off;

	if(ip4h + 1 > data_end) {
		return XDP_PASS;
	}

#if 0
__u32 src = ip4h->saddr;
__u32 dst = ip4h->daddr;
#endif
	return parse_packet(ctx, ip4h + 1, ip4h->protocol);
}

static __always_inline int do_ipv6(struct xdp_md *ctx, __u64 nh_off) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	struct ipv6hdr *ip6h = data + nh_off;

	if(ip6h + 1 > data_end) {
		return XDP_PASS;
	}
#if 0
__be32 src[4];
__be32 dst[4];
memcpy(src, ip6h->saddr.s6_addr32, 16);
memcpy(dst, ip6h->daddr.s6_addr32, 16);
#endif

	return parse_packet(ctx, ip6h + 1, ip6h->nexthdr);
}

SEC("xdp_prog")
int  xdp_prog0(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u16 eth_proto = 0;
        __u64 l3_offset = 0;

	/* eth */
	if(!(parse_eth(eth, data_end, &eth_proto, &l3_offset))) {
		goto out;
	}

	/* proto */
	switch(eth_proto) {
		case ETH_P_IP:
			return do_ipv4(ctx, l3_offset);
		break;
		case ETH_P_IPV6:
			return do_ipv6(ctx, l3_offset);
		break;
		case ETH_P_ARP:
			goto out;
		break;
		default:
			goto out;
	}
out:
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

