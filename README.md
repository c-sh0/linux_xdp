# linux_xdp
Linux XDP (eXpress Data Path)

## Description
Development enviorment for building XDP programs. eBPF/XDP is in active development and the process for building/installing applications has and will certainly change.  
Recommended Reading:  
https://facebookmicrosites.github.io/bpf/blog/2020/02/19/bpf-portability-and-co-re.html#the-problem-of-bpf-portability

Tested on:
- VirtialBox VM (Memory: 2GB)
- CentOS 8.3.2011, 7.9.2009
- kernel-ml-5.10.14

## Prerequisites
##### Kernel
To install the latest kernel-ml and development packages
```
yum install --enablerepo=elrepo-kernel kernel-ml
yum install kernel-ml-{headers,devel,tools,tools-libs,tools-libs-devel}
```
##### Compilers
It's best to use the latest available compiler versions. Using gcc and clang/llvm from the Software Collections (SCL) repository may not work with `libbpf` 100% of the time. Your mileage may vary.
```
yum install centos-release-scl
yum install gcc-toolset-9 devtoolset-8 llvm-toolset binutils-devel readline-devel elfutils-libelf-devel

scl enable devtoolset-8 bash
scl enable llvm-toolset-7 bash
```
https://wiki.centos.org/AdditionalResources/Repositories/SCL
https://www.softwarecollections.org/en/scls/?search=Developer+Toolset
#### Building Clang/LLVM from source
Install to `/opt/llvm-x.x.x`
```
# Requires updated Cmake to build (using cmake from SCL repo should work)
yum install llvm-toolset-7-cmake
scl enable llvm-toolset-7-cmake bash

git clone https://github.com/llvm/llvm-project.git
cd ./llvm-project

# Choose a version
git checkout llvmorg-11.1.0

mkdir ../build && cd ../build
cmake ../llvm-project/llvm \
   -DLLVM_TARGETS_TO_BUILD="BPF;X86" \
   -DLLVM_ENABLE_PROJECTS=clang \
   -G "Unix Makefiles" \
   -DBUILD_SHARED_LIBS=OFF \
   -DCMAKE_BUILD_TYPE=Release \
   -DLLVM_BUILD_RUNTIME=OFF

# install to /opt/llvm-VERSION
cmake -DCMAKE_INSTALL_PREFIX=/opt/llvm-11.1.0 -P cmake_install.cmake
```
https://clang.llvm.org/get_started.html

## iproute2
You may receive an error when using ip route *`error: No ELF library support compiled in`* If so, just upgrade. Quick install to `/opt/iproute2`
```
git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git
cd iproute2/
./configure
make
make install PREFIX=/opt/iproute2 SBINDIR=/opt/iproute2/sbin
```
## Build
Clone this repository, initialize and/or update the `libbpf` submodule, and just run `make`
```
git submodule update --init

# (optional) To update `libbpf` to latest upstream version
git submodule update --remote --merge

make
```

## Attaching the programs (object files)
Using iproute (Note: iproute does not have bpf/xdp capabilities on some older systems, upgrade to iproute2)
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

## Notes
- These types of warning's can be ignored when calling `bpf_prog_load()`
  https://github.com/libbpf/libbpf-bootstrap/issues/12#issuecomment-785303374
  ```
  libbpf: elf: skipping unrecognized data section(4) .rodata.str1.1
  ```
- Look into using any of the following upstream packages (compatibility issues?)
  - libbpf :- A mirror of bpf-next linux tree (incomplete?)
  - libxdp :- libxdp library for managing XDP programs

## References
 1. [BPF/libbpf](https://github.com/libbpf/libbpf) - Mirror of bpf-next Linux source tree's tools/lib/bpf
 2. [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) - XDP Hands-On Tutorial
