# linux_xdp
Linux XDP (eXpress Data Path)

## Description
Test enviorment for building XDP programs. eBPF/XDP is in active development and the process for building/installing applications has and will certainly change.

Tested on:
- VirtialBox VM (Memory: 2GB)
- CentOS 8.3.2011, 7.9.2009
- kernel-ml-5.10.14

## Prerequisites
- kernel devel and headers packages
- gcc and clang toolsets
```
yum install --enablerepo=elrepo-kernel kernel-ml kernel-ml-{headers,devel,tools,tools-libs,tools-libs-devel}
yum install gcc-toolset-9 devtoolset-8 llvm-toolset binutils-devel readline-devel elfutils-libelf-devel
```
## iproute2
You may receive an error when using ip route *`error: No ELF library support compiled in`* If so, just upgrade
```
git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git
cd iproute2/
./configure
make
make install PREFIX=/opt/iproute2 SBINDIR=/opt/iproute2/sbin
```
## Build
Clone this repository, initialize the `libbpf` submodule, and just run `make`
```
scl enable devtoolset-8 bash
scl enable llvm-toolset-7 bash

git submodule update --init
make
```
Update `libbpf` to latest upstream version, just do
```
git submodule update --remote --merge
```

## Attaching the programs
- Using iproute (Note: iproute does not have bpf/xdp capabilities on some older systems)
```
# <section> (see the SEC() name in /path/to/xdp_prog_file.c)
ip link set dev <iface> xdp obj </path/to/xdp_prog_file.o> sec <section name>

# Status
ip link show dev <iface>

# Remove
ip link set dev <iface> xdp off
```
## Debugging
- bpf_printk() writes to /sys/kernel/debug/tracing/trace_pipe
- bpftool: `yum install bpftool`
- [xdp-tools](https://github.com/xdp-project/xdp-tools) - Utilities and example programs for use with XDP

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

## References
 1. [BPF/libbpf](https://github.com/libbpf/libbpf) - Mirror of bpf-next Linux source tree's tools/lib/bpf
 2. [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) - XDP Hands-On Tutorial
