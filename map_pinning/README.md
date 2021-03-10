# Pinned bpf map example
Pinning is not required to access maps from within the same program (deamon?) however, pinning is required if other userspace applications needs to interact with those maps

## Usage
```
Usage: maps_ctl [OPTIONS]

 Options:

  -d, --dev <device>  Use <device> (required)
  -r, --remove        Remove program
  -S, --skb-mode      Use SKB mode
  -u, --update <value1> <value2>  Update map data (read by kernel program)
```

## Example
```
* Load program on interface `lo` SKB mode
    ./maps_ctl -d lo -S

* Read/Update map
    ./maps_ctl -d lo -u 123 8888
    [INFO]:[maps_ctl.c:192] - (prog_info) id:124 name:maps_prog prog_fd:3
    [INFO]:[maps_ctl.c:304] - Lookup: map_fd:4 value1:0 value2:0
    [INFO]:[maps_ctl.c:314] - Update: map_fd:4 value1:123 value2:8888

* Check kernel program can read the values (send some traffic to the interface)
    ping 127.0.0.1
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.055 ms

    #- In another terminal
    cat /sys/kernel/debug/tracing/trace_pipe
    ping-6487    [000] d.s1 76438.771158: bpf_trace_printk: MAPS_SIMPLE: data->value1:123 data->value2:8888

* Remove program
    ./maps_ctl -d lo -r
```
## Pinning maps using bpftool
You can pin maps just by using bpftool
```
yum install bpftool
```
In this example the following map declaration was used
```
struct bpf_map_def SEC("maps") my_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(__u32),
        .value_size  = 16 * sizeof(char),
        .max_entries = 1,
};
```
```
* Load the kernel object file (iproute2)
    ip link set dev lo xdp obj maps_kernel.o sec maps_simple

* Get map id
    bpftool map
    228: hash  flags 0x0
    key 4B  value 16B  max_entries 1  memlock 4096B

* Pin the map using map id
* note: /sys/fs/bpf/<map_name> differs from the map declaration in the kernel program, This can be convenient since <map_name> can be anything you want
   bpftool map pin id 228 /sys/fs/bpf/test_map

   ls -la /sys/fs/bpf/test_map
   -rw-------. 1 root root 0 Mar 04 01:40 /sys/fs/bpf/test_map

   bpftool map dump pinned /sys/fs/bpf/test_map
   Found 0 elements

* Add data, in hex, to the map. The key in this example is just 0 and value is the string: "Test123Test12346"
    bpftool map update id 228 key 0 0 0 0 value 0x54 0x65 0x73 0x74 0x31 0x32 0x33 0x54 0x65 0x73 0x74 0x31 0x32 0x33 0x34 0x36

* Verify it worked
    bpftool map dump pinned /sys/fs/bpf/test_map
    key: 00 00 00 00  value: 54 65 73 74 31 32 33 54  65 73 74 31 32 33 34 36
    Found 1 element

* Cleanup
    ip link set dev lo xdp off
    rm -f /sys/fs/bpf/test_map
```

