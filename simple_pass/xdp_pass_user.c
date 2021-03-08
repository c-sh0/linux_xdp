#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* basic test load, unload functions (just to make sure libbpf works)*/
static const char *obj_file = "./xdp_pass_kern.o";
static const char *iface = "lo";

int main(void) {
	int prog_fd = -1;
	struct bpf_object *obj;
	int ifindex;
	int err;
	//uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	uint32_t xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE;

	ifindex = if_nametoindex(iface);
	printf("ifindex:%d obj_file:%s\n",ifindex,obj_file);

	printf(" - bpf_prog_load()...\n");
	err = bpf_prog_load(obj_file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
	if(err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n", obj_file, err, strerror(-err));
		return -1;
	}

	/* link */
	printf(" - bpf_set_link_xdp_fd() : Load ...\n");
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if(err  < 0) {
		fprintf(stderr, "ERR: " "ifindex(%d) link set xdp fd failed (%d): %s\n", ifindex, -err, strerror(-err));
		return -1;
	}

	/* unlink */
	printf(" - bpf_set_link_xdp_fd() : Remove ...\n");
	err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	if(err < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n", err, strerror(-err));
		return -1;
	}

	printf(" - Verify xdp program is removed, run command: `ip link show dev %s`\n",iface);

 return 0;
}

