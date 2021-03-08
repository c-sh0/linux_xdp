/*
 *
 * Simple xdp program to test maps
 * bpf_printk() messages are written to /sys/kernel/debug/tracing/trace_pipe
 *
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "maps_common.h"

struct bpf_map_def SEC("maps") array_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct map_data_t),
	.max_entries = 1,
};

SEC("maps_simple")
int maps_prog(struct xdp_md *ctx) {

	struct map_data_t *data;
	__u32 key = 0;

	/* array map lookup */
	data = bpf_map_lookup_elem(&array_map, &key);
	if(!data) {
		return(XDP_ABORTED);
	}

	bpf_printk("MAPS_SIMPLE: data->value1:%u data->value2:%u",data->value1,data->value2);

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

