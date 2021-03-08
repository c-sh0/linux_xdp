#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <ctype.h>
#include <libgen.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "maps_common.h"

const char *xdp_obj_file = "maps_kernel.o";
const char *map_basedir	 = "/sys/fs/bpf"; /* dir should already exist */

static const struct option long_options[] = {
	{"dev",         required_argument,   NULL, 'd' },
	{"skb-mode",    no_argument,         NULL, 'S' },
	{"update",      required_argument,   NULL, 'u' },
	{"remove",      no_argument,         NULL, 'r' },
	{0, 0, NULL,  0 }
};

static void usage(const char *prog) {
	const char *str =
		"Usage: %s [OPTIONS]\n\n"
		" Options:\n\n"
		"  -d, --dev <device>  Use <device> (required)\n"
		"  -r, --remove        Remove program\n"
		"  -S, --skb-mode      Use SKB mode\n"
		"  -u, --update <value1> <value2>  Update map data (read by kernel program)\n"
		"\n";

	fprintf(stderr,str,prog);
	exit(-EINVAL);
}

/* get map fd by name */
int get_map_fd(const char *pin_dir, const char *mapname, struct bpf_map_info *info) {
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if(len < 0) {
		fprintf(stderr, "[ERROR]:[%s:%d] - map filename\n",__FILE__,__LINE__);
		return -1;
	}

	fd = bpf_obj_get(filename);
	if(fd < 0) {
		fprintf(stderr, "[ERROR]:[%s:%d] - Failed to open:%s err(%d):%s\n",__FILE__,__LINE__,filename,errno,strerror(errno));
		return -1;
	}

	if(info) {
		err = bpf_obj_get_info_by_fd(fd, info, &info_len);
		if(err) {
			fprintf(stderr, "[ERROR]:[%s:%d] - bpf_obj_get_info_by_fd - err(%d):%s\n",__FILE__,__LINE__,errno,strerror(errno));
			return -1;
		}
	}

	return fd;
}

/* detach and unpin maps (note: force unload, doesn't check for exsisting program/maps) */
int do_detach(int ifindex, __u32 xdp_flags, const char *pin_dir) {
	struct bpf_object *bpf_obj;
	int prog_fd, err;

	/* we should know what flags were passed when attaching the program,
	 * for now just clearing flags and unload works */
	xdp_flags &= ~XDP_FLAGS_MODES; /* clear flags */

	err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	if(err  < 0) {
		fprintf(stderr, "[ERROR]:[%s:%d] - detach failed! %s\n",__FILE__,__LINE__,strerror(errno));
		return -1;
	}

	/* populate bpf_obj from xdp_obj_file to get map information (is there a better way?) */
	err = bpf_prog_load(xdp_obj_file, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
	if(err) {
		fprintf(stderr, "[ERROR]:[%s:%d] - loading BPF-OBJ file(%s) (%d): %s\n",__FILE__,__LINE__,xdp_obj_file,-err,strerror(-err));
		return -1;
	}

	/* calls unlink(3) on map_filename */
	err = bpf_object__unpin_maps(bpf_obj, pin_dir);
	if (err) {
		fprintf(stderr, "[ERROR]:[%s:%d] - unpin maps (%d): %s\n",__FILE__,__LINE__,-err,strerror(-err));
		return -1;
	}

	printf("[INFO]:[%s:%d] - Success: Removed XDP prog from ifindex:%d\n",__FILE__,__LINE__,ifindex);
	return 0;
}

/* attach and pin maps */
int do_attach(int ifindex, __u32 xdp_flags, const char *pin_dir) {
	struct bpf_prog_info prog_info = {};
	struct xdp_link_info link_info = {};
	struct bpf_object *bpf_obj = NULL;
	int err = -1;
	int prog_fd = -1;
	__u32 prog_id = 0;
	__u32 info_sz = sizeof(prog_info);

	/* check if a program is already loaded
	 * example in: https://github.com/xdp-project/xdp-tools/blob/master/lib/libxdp/libxdp.c */
	err = bpf_get_link_xdp_info(ifindex, &link_info, sizeof(link_info), 0);
	if(err) {
		fprintf(stderr, "[ERROR]:[%s:%d] - bpf_get_link_xdp_info (err=%d): %s\n",__FILE__,__LINE__,-err,strerror(-err));
		return -1;
	}

	/* xdp_flags, prog_id */
	// case XDP_ATTACHED_MULTI: ??
	switch(link_info.attach_mode) {
		case XDP_ATTACHED_SKB:
			prog_id = link_info.skb_prog_id;
			prog_fd = bpf_prog_get_fd_by_id(prog_id);
		break;

		case XDP_ATTACHED_DRV:
			prog_id = link_info.drv_prog_id;
			prog_fd = bpf_prog_get_fd_by_id(prog_id);
		break;

		case XDP_ATTACHED_HW:
			prog_id = link_info.hw_prog_id;
			prog_fd = bpf_prog_get_fd_by_id(prog_id);
		break;

		/* No program found, do attach */
		default:
			/* default driver mode */
			if(!(xdp_flags & XDP_FLAGS_SKB_MODE)) {
				xdp_flags |= XDP_FLAGS_DRV_MODE;
			}

			/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
			 * loading this into the kernel via bpf-syscall
			 * NOTE: bpf_prog_load() also calls bpf_prog_load_xattr() */
			err = bpf_prog_load(xdp_obj_file, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
			if(err) {
				fprintf(stderr, "[ERROR]:[%s:%d] - loading BPF-OBJ file(%s) (%d): %s\n",__FILE__,__LINE__,xdp_obj_file,-err,strerror(-err));
				return -1;
			}

			/* load xdp kernel object */
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
			switch(-err) {
				case EBUSY:
				case EEXIST:
					printf("[INFO]:[%s:%d] - ifindex:%d\n",__FILE__,__LINE__,ifindex);
				break;
				case EOPNOTSUPP:
					fprintf(stderr, "[ERROR]:[%s:%d] - xdp_flags not supported, try -S,--skb-mode\n",__FILE__,__LINE__);
					return -1;
				break;

				default:
					/* This will pin all maps */
					err = bpf_object__pin_maps(bpf_obj, pin_dir);
					if(err) {
						fprintf(stderr, "[ERROR]:[%s:%d] - bpf_object__pin_maps (%d): %s\n",__FILE__,__LINE__,-err,strerror(-err));
						return -1;
					}

					printf("[INFO]:[%s:%d] Program loaded OK - ifindex:%d\n",__FILE__,__LINE__,ifindex);
				break;
			}
		break;
	}

	/* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &info_sz);
	if(err) {
		fprintf(stderr, "[ERROR]:[%s:%d] - bpf_obj_get_info_by_fd (%d): %s\n",__FILE__,__LINE__,-err,strerror(-err));
		return -1;
	}

	printf("[INFO]:[%s:%d] - (prog_info) id:%d name:%s prog_fd:%d\n",__FILE__,__LINE__,prog_info.id,prog_info.name,prog_fd);

	return prog_fd;

}

int main(int argc, char **argv) {
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char ifbuf[IF_NAMESIZE], *ifname;
	char map_dir[PATH_MAX];
	int opt, optindex, len;
	int do_remove = -1;
	int do_update = -1;
	int ifindex = -1;
	__u32 xdp_flags =  0;

	while((opt = getopt_long(argc, argv, "Srd:u:", long_options, &optindex)) != -1) {
		switch(opt) {
			case 'd':
				if(strlen(optarg) >= IF_NAMESIZE) {
					fprintf(stderr, "[ERROR]:[%s:%d] - device name too long\n",__FILE__,__LINE__);
					goto fail_opt;
				}
				ifname = (char *)&ifbuf;
				strncpy(ifname, optarg, IF_NAMESIZE);

				ifindex = if_nametoindex(ifname);
				if(ifindex == 0) {
					fprintf(stderr, "[ERROR]:[%s:%d] - %s device not found\n",__FILE__,__LINE__,ifname);
					goto fail_opt;
				}

				/* path to pin maps, ifname as subdir */
				len = snprintf(map_dir, PATH_MAX, "%s/%s", map_basedir, ifname);
				if(len < 0) {
					fprintf(stderr, "[ERROR]:[%s:%d] - creating pin map path\n",__FILE__,__LINE__);
					return -1;
				}
			break;

			case 'r':
				do_remove = 1;
			break;

			case 'S':
				//xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST; /* force load */
				xdp_flags &= ~XDP_FLAGS_MODES;    /* clear flags */
				xdp_flags |=  XDP_FLAGS_SKB_MODE; /* set flag */
			break;

			case 'u':
				do_update = 1;
			break;

			default:
				fail_opt:
				usage(basename(argv[0]));
		}
	}

	/* required option --dev */
	if(ifindex == -1) {
		fprintf(stderr, "[ERROR]:[%s:%d] - required option --dev missing\n",__FILE__,__LINE__);
		usage(basename(argv[0]));

	} else {
		/* remove program and unpin maps */
		if(do_remove == 1) {
			if(do_detach(ifindex, xdp_flags, map_dir) == -1) {
				fprintf(stderr, "[ERROR]:[%s:%d] - do_detach (-1)\n",__FILE__,__LINE__);
				return -1;
			}
			return 1;
		}

		/* increase rlimit, avoid common `ulimit -l` errors
	 	 * https://lore.kernel.org/bpf/20191216181204.724953-1-toke@redhat.com/ */
		if(setrlimit(RLIMIT_MEMLOCK, &r)) {
			fprintf(stderr, "[ERROR]:[%s:%d] - %s\n",__FILE__,__LINE__,strerror(errno));
			return -ENOMEM;
		}

		/* attach program and pin maps */
		if(do_attach(ifindex, xdp_flags, map_dir) == -1) {
			fprintf(stderr, "[ERROR]:[%s:%d] - do_attach (-1)\n",__FILE__,__LINE__);
			return -1;
		}

		/* lookup/update map */
		if(do_update == 1) {
			struct bpf_map_info info = { 0 };
			struct map_data_t data;
			int map_fd = -1;
			__u32 key = 0;

			if(argc != 6) {
				fprintf(stderr, "[ERROR]:[%s:%d] - Ivalid update args\n",__FILE__,__LINE__);
				usage(basename(argv[0]));
			}

			map_fd = get_map_fd(map_dir, "array_map", &info);
			if(map_fd == -1) {
				fprintf(stderr, "[ERROR]:[%s:%d] - get_map_fd (%d)\n",__FILE__,__LINE__,map_fd);
				return -1;
			}

			/* lookup current values */
			if((bpf_map_lookup_elem(map_fd, &key, &data)) != 0) {
				fprintf(stderr, "[ERROR]:[%s:%d] - bpf_map_lookup_elem failed!\n",__FILE__,__LINE__);
				return -1;
			}

			printf("[INFO]:[%s:%d] - Lookup: map_fd:%d value1:%u value2:%u\n",__FILE__,__LINE__,map_fd,data.value1,data.value2);

			data.value1 = atoi(argv[4]);
			data.value2 = atoi(argv[5]);

			/* update new values */
			if(bpf_map_update_elem(map_fd, &key, &data, BPF_ANY) != 0) {
				fprintf(stderr, "[ERROR]:[%s:%d] - bpf_map_update_elem failed!\n",__FILE__,__LINE__);
				return -1;
			}
			printf("[INFO]:[%s:%d] - Update: map_fd:%d value1:%u value2:%u\n",__FILE__,__LINE__,map_fd,data.value1,data.value2);
		}

	}

	return 0;
}

