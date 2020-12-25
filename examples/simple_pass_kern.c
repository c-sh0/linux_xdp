/*
 *
 * Simple xdp program pass all connections,
 * bpf_printk() messages are written to /sys/kernel/debug/tracing/trace_pipe
 *
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("simple_pass")
int xdp_prog(struct xdp_md *ctx) {

	bpf_printk("DEBUG: XDP_SIMPLE PASS ....\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

