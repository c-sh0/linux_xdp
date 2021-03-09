/*
 * NOTES:
 * -----------------------------
 * Flags for BPF_MAP_UPDATE_ELEM command (key/value pair)
 * BPF_ANY         0 create new key/value or update existing
 * BPF_NOEXIST     1 create new key/value if it didn't exist
 * BPF_EXIST       2 update existing key/value
 *
 * [/csh:]> date "+%D"
 * 03/09/21
*/
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

#include "common.h"

const char *xdp_obj_file = "port_ticker_kernel.o";
const char *map_basedir  = "/sys/fs/bpf"; /* dir should already exist */

static const struct option long_options[] = {
	{"dev",         required_argument,      NULL, 'd' },
	{"skb-mode",    no_argument,            NULL, 'S' },
	{"ignore",      required_argument,      NULL, 'i' },
	{"icmp-enable", required_argument,      NULL, 'I' },
	{"list", 	no_argument,            NULL, 'l' },
	{"threshold", 	required_argument,  	NULL, 't' },
	{"remove", 	no_argument,		NULL, 'r' },
	{0, 0, NULL,  0 }
};

static void usage(const char *prog) {
	const char *str =
		"\nUsage: %s [OPTIONS]\n\n"
		" Options:\n\n"
		"  -d, --dev <device>         Use <device> (required)\n"
		"  -S, --skb-mode             Use SKB mode (default: try driver mode)\n"
		"  -i, --ignore <src_ip>      Ignore all <src_ip> packets\n"
		"  -I, --icmp-enable [0,1]    Disable/Enable icmp responses (default disabled: 0)\n"
		"  -t, --threshold <n>        Threshold to record the number of times a src_ip changed dest_port (default: 20)\n"
		"  -l, --list                 List source ip and port change counters\n"
		"  -r, --remove               Remove program from <device>\n"
		"\n Examples:\n\n"
		"    %s -d eth0 -S		 :- Install program on eth0 SKB mode\n"
		"    %s -d eth0 -i 192.168.1.20  :- Add ip 192.168.1.20 to the ignore list (return traffic from any outbound connections?)\n"
		"    %s -d eth0 -I 1             :- Enable ICMP responses\n"
		"    %s -d eth0 -t 200           :- Increase tracking threshold\n"
		"    %s -d eth0 -l               :- List logged source ip's whos ports have changed > threshold\n"
		"\n";

	fprintf(stderr,str,prog,prog,prog,prog,prog,prog);

	exit(-1);
}

/* get map fd by name, see SEC("maps") in kernel program */
int get_map_fd(const char *pin_dir, const char *mapname, struct bpf_map_info *info) {
	char filename[PATH_MAX];
	int err, len, fd;
	__u32 info_len = sizeof(*info);

	len = snprintf(filename, PATH_MAX, "%s/%s", pin_dir, mapname);
	if(len < 0) {
		fprintf(stderr, "[ERROR]:[%s:%d] - map filename\n",__FILE__,__LINE__);
		return -1;
	}

	/* FD from pinned maps (*map_basedir/<interface>/<name>) */
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

	/* populate bpf_obj struct by reading xdp_obj_file to get map information
	 * hmmm, is there a better way to do this? what does `bpftool` do ? */
	err = bpf_prog_load(xdp_obj_file, BPF_PROG_TYPE_XDP, &bpf_obj, &prog_fd);
	if(err) {
		fprintf(stderr, "[ERROR]:[%s:%d] - loading BPF-OBJ file(%s) (%d): %s\n",__FILE__,__LINE__,xdp_obj_file,-err,strerror(-err));
		return -1;
	}

	/* calls unlink(3) on map_filename */
	err = bpf_object__unpin_maps(bpf_obj, pin_dir);
	if(err) {
		fprintf(stderr, "[WARN]:[%s:%d] - unpin maps (%d): %s\n",__FILE__,__LINE__,-err,strerror(-err));
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
				case EBUSY: /* fall through */
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

/* convert to ipv4 string */
int get_ipv4_str(uint32_t addr, char *buf) {
	uint8_t bytes[4] = {0};

	bytes[0] = addr & 0xFF;
	bytes[1] = (addr >> 8) & 0xFF;
	bytes[2] = (addr >> 16) & 0xFF;
	bytes[3] = (addr >> 24) & 0xFF;

	snprintf(buf, INET_ADDRSTRLEN, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	return(1);
}

/* bpf_map_get_next_key() `next_key` contains the key's value */
void do_report(int map_fd) {
	struct ipaddr_info_t data;
	char ip[INET_ADDRSTRLEN];
	__u32 key, next_key;

	//printf("[DEBUG]:[%s:%d] Do report map_fd:%d\n",__FILE__,__LINE__,map_fd);

	printf("\nReport:\n\n--------------------------------------\n");
	printf("Source IP\t|  Change count\n");
	printf("--------------------------------------\n");

	while(bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {

		bpf_map_lookup_elem(map_fd, &next_key, &data);
		get_ipv4_str(next_key, ip);
		printf("%s\t|  %u\n",ip,data.change_cnt);

		key = next_key;
 	}

	printf("\n\n");
	return;
}

int main(int argc, char **argv) {
        struct sockaddr_in sa;
	char ifbuf[IF_NAMESIZE], *ifname;
	char map_dir[PATH_MAX];
	int ifindex = -1;
	int opt_remove = -1;
	int opt_ignore = -1;
	int opt_list = -1;
	int opt, optindex, len, ret;
	__u32 xdp_flags =  0;
	__u32 ignore_addr;

	/* default settings */
	struct ctrl_settings_t ctl_settigs = {
		.threshold   = 20,
		.enable_icmp = 0,
	};

	while((opt = getopt_long(argc, argv, "rlSd:t:I:i:o:", long_options, &optindex)) != -1) {
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

			case 'S':
				//xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST; /* force load */
				xdp_flags &= ~XDP_FLAGS_MODES;    /* clear flags */
				xdp_flags |=  XDP_FLAGS_SKB_MODE; /* set flag */
			break;

			case 'i':
				if(strlen(optarg) >= INET_ADDRSTRLEN) {
					fprintf(stderr, "[ERROR]:[%s:%d] -i,--ignore ip address too long\n",__FILE__,__LINE__);
					goto fail_opt;
				}

				/* todo?: inet_pton() also supports IPv6 addresses */
				ret = inet_pton(AF_INET, optarg, &(sa.sin_addr));
				if(ret <= 0) {
					fprintf(stderr, "[ERROR]:[%s:%d] -i,--ignore ip address invalid\n",__FILE__,__LINE__);
					goto fail_opt;
				}

				/* note: 0 (0.0.0.0) is a valid ipv4 address, refer to the kernel program for
				 * these corner cases */
				ignore_addr = sa.sin_addr.s_addr;
				opt_ignore = 1;
				/* Having a programmer's calculator and/or ip addr converter can be handy
				 * for debugging https://www.vultr.com/resources/ipv4-converter/ */
				printf("[DEBUG]:[%s:%d] - ignore ip:%u str:%s\n",__FILE__,__LINE__,ignore_addr,optarg);
			break;

			case 'I':
				ctl_settigs.enable_icmp = atoi(optarg);
				if(ctl_settigs.enable_icmp > 1) {
					fprintf(stderr, "ERROR: -I,--icmp-enable invalid: %u\n",ctl_settigs.enable_icmp);
					goto fail_opt;
				}
			break;

			case 't':
				ctl_settigs.threshold = atoi(optarg);
			break;

			case 'l':
				opt_list = 1;
			break;

			case 'r':
				opt_remove = 1;
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

	/* todo?: clean up the code/flow? (i got lazy ;-P) */
	} else {
		struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
		struct bpf_map_info ctl_info = {0};
		int ctl_fd = -1;
		__u32 ctl_key = 0;


		printf("[DEBUG]:[%s:%d] - ifname:%s ifindex:%d mapdir:%s\n",__FILE__,__LINE__,ifname,ifindex,map_dir);
		printf("[DEBUG]:[%s:%d] - argc:%d optind:%d\n",__FILE__,__LINE__,argc,optind);

		/* increase rlimit, avoid common `ulimit -l` errors
		 * https://lore.kernel.org/bpf/20191216181204.724953-1-toke@redhat.com/ */
		if(setrlimit(RLIMIT_MEMLOCK, &r)) {
			fprintf(stderr, "[ERROR]:[%s:%d] - %s\n",__FILE__,__LINE__,strerror(errno));
			return -ENOMEM;
		}

		/* remove program and unpin maps */
		if(opt_remove == 1) {
			if(do_detach(ifindex, xdp_flags, map_dir) == -1) {
				fprintf(stderr, "[ERROR]:[%s:%d] - do_detach (-1)\n",__FILE__,__LINE__);
				return -1;
			}
			return 1;
		}

		/* attach program and pin maps */
		if(do_attach(ifindex, xdp_flags, map_dir) == -1) {
			fprintf(stderr, "[ERROR]:[%s:%d] - do_attach (-1)\n",__FILE__,__LINE__);
			return -1;
		}

		/* see SEC("maps") in kernel program */
		ctl_fd = get_map_fd(map_dir, "ctrl_map", &ctl_info);
		if(ctl_fd == -1) {
			fprintf(stderr, "[ERROR]:[%s:%d] - get_map_fd (%d)\n",__FILE__,__LINE__,ctl_fd);
			return -1;
		}

		#if 0
		/* lookup current settinigs ? */
		if((bpf_map_lookup_elem(ctl_fd, &ctl_key, &ctl_settigs)) != 0) {
			fprintf(stderr, "[ERROR]:[%s:%d] - bpf_map_lookup_elem failed!\n",__FILE__,__LINE__);
			return -1;
		}
		#endif

		/* update control settings */
		if(bpf_map_update_elem(ctl_fd, &ctl_key, &ctl_settigs, BPF_ANY) != 0) {
			fprintf(stderr, "[ERROR]:[%s:%d] - bpf_map_update_elem failed!\n",__FILE__,__LINE__);
			return -1;
		}
		printf("[DEBUG]:[%s:%d] - Control settings (ctl_fd:%u ctl_key:%u threshold:%u enable_icmp:%u)\n",__FILE__,__LINE__,ctl_fd,ctl_key,ctl_settigs.threshold,ctl_settigs.enable_icmp);

		/* update ignore ip map */
		if(opt_ignore == 1) {
			struct bpf_map_info i_info = {0};
			struct ignore_addr_t i_data;
			int i_fd = -1;
			__u32 i_key;

			if(argc != 5) {
				fprintf(stderr, "[ERROR]:[%s:%d] -i,--ignore Invalid number of arguments\n",__FILE__,__LINE__);
				usage(basename(argv[0]));
			}

			/* see SEC("maps") in kernel program */
			i_fd = get_map_fd(map_dir, "ignore_map", &i_info);
			if(i_fd == -1) {
				fprintf(stderr, "[ERROR]:[%s:%d] - get_map_fd (%d)\n",__FILE__,__LINE__,i_fd);
				return -1;
			}

			/* map data, use ip addr as key */
			i_key = ignore_addr;
			i_data.ignore = 1;

			/* The `ignore_map` is a BPF_MAP_TYPE_LRU_HASH, no need to lookup for an existing entry
			 * BPF_MAP_TYPE_LRU_HASH:
			 *	- Each hash maintains an LRU (least recently used) list for each bucket to inform delete when the hash bucket fills up
			 * BPF_ANY:
			 *     - 0 create new key/value or update existing */
			if(bpf_map_update_elem(i_fd, &i_key, &i_data, BPF_ANY) != 0) {
				fprintf(stderr, "[ERROR]:[%s:%d] - bpf_map_update_elem failed!\n",__FILE__,__LINE__);
				return -1;
			}
			printf("[DEBUG]:[%s:%d] - Ignore IP address added (i_fd:%u key:%u value:%u)\n",__FILE__,__LINE__,i_fd,i_key,i_data.ignore);
			return 1;
		}

		/* report */
		if(opt_list == 1) {
			int report_fd;
			struct bpf_map_info l_info = {0};

			if(argc != 4) {
				fprintf(stderr, "[ERROR]:[%s:%d] -l,--list Invalid number of arguments\n",__FILE__,__LINE__);
				usage(basename(argv[0]));
			}

			/* see SEC("maps") in kernel program */
			report_fd = get_map_fd(map_dir, "report_map", &l_info);
			if(report_fd == -1) {
				fprintf(stderr, "[ERROR]:[%s:%d] - get_map_fd (%d)\n",__FILE__,__LINE__,report_fd);
				return -1;
			}

			do_report(report_fd);
		}

	}

	return 0;
}

