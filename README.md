# linux_xdp
Linux XDP (eXpress Data Path)

## Description
Test enviorment for building XDP programs. eBPF/XDP is in active development and the process for building/installing applications has and will certainly change.

Tested on:
- VirtialBox VM (Memory: 2GB)
- CentOS 8.3.2011
- kernel-ml-5.10.2-1.el8.elrepo

## Prerequisites
- kernel devel and headers packages
- gcc and clang toolsets
```
yum install --enablerepo=elrepo-kernel kernel-ml-devel kernel-ml-headers
yum install gcc-toolset-9 llvm-toolset binutils-devel readline-devel elfutils-libelf-devel
```

## Build
Clone this repository, initialize the `libbpf` submodule, and just run `make`
```
cd linux_xdp
git submodule update --init
make
```

## Attaching the programs
- Using iproute (Note: iproute does not have bpf/xdp capabilities on some older systems)
```
# <section> (see the SEC() name in /path/to/xdp_prog_file.c)
ip link set dev lo xdp obj </path/to/xdp_prog_file.o> sec <section name>

# Status
ip link show dev <iface>

# Remove
ip link set dev <iface> xdp off
```

## Build libbpf-devel package
Build a RPM
```
yum install rpm-build
make package
yum localinstall ./rpmbuild/RPMS/x86_64/libbpf-devel-0.1.0-1.x86_64.rpm
```

## TODO
- Userspace programs
- More complex examples
- Utilize any of the following upstream packages (compatibility issues?)
  - libbpf :- A mirror of bpf-next linux tree (incomplete?)
  - libxdp :- libxdp library for managing XDP programs
  - xdp-tools :- XDP utilities (broken: https://github.com/xdp-project/xdp-tools/issues/82)

## References
 1. [BPF/libbpf](https://github.com/libbpf/libbpf) - Mirror of bpf-next Linux source tree's tools/lib/bpf
 2. [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) - XDP Hands-On Tutorial
 3. [xdp-tools](https://github.com/xdp-project/xdp-tools) - Utilities and example programs for use with XDP

