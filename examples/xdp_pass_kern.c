/*
 * Simple xdp program pass all traffic
 * bpf_printk() messages are written to /sys/kernel/debug/tracing/trace_pipe
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp_pass")
int xdp_pass_prog(struct xdp_md *ctx) {

	bpf_printk("DEBUG SIMPLE XDP_PASS");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

