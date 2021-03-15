# Process payloads - DPI (Deep Packet Inspection)
Simple program to show how you can process/store packet payloads.
* Creates a simple map to store the payload
* Supports IPV6/IPv4
* UDP and TCP
* Tested on kernel-ml-5.10.14, Clang/LLVM 11.x

## Example session
```
* Load using iproute
    ip link set dev lo xdp obj process_payload_kern.o sec xdp_prog

* Initialze the map with some data
    bpftool map
    68: hash  flags 0x0
        key 4B  value 32B  max_entries 1  memlock 4096B

    bpftool map update id 68 key 0 0 0 0 value 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

    bpftool map dump id 68
    key:
    00 00 00 00
    value:
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
    Found 1 element

* In another terminal, monitor the trace log
    cat /sys/kernel/debug/tracing/trace_pipe

* Send some test UDP data (UDP is stateless so there is no need to have a listening service)
    echo 'PayloadPayloadPayloadPayloadPayload' | nc -u 127.0.0.1 80

* Send some test TCP data (you'll need to have a listening service)
    curl http://127.0.0.1/
    curl -g -6 "http://[::1]:80/IPv6"

* Sample trace log output
    nc-6027    [001] d.s1 100191.159911: bpf_trace_printk: [DEBUG]: IPPROTO_UDP
    nc-6027    [001] d.s1 100191.159922: bpf_trace_printk: [DEBUG]: sport:58455 dport:80
    nc-6027    [001] d.s1 100191.159923: bpf_trace_printk: [DEBUG]: payload = PayloadPayloadPayloadPayloadPayl

    curl-6188    [000] d.s1 100389.331948: bpf_trace_printk: [DEBUG]: IPPROTO_TCP
    curl-6188    [000] d.s1 100389.331949: bpf_trace_printk: [DEBUG]: sport:46474 dport:80
    curl-6188    [000] d.s1 100389.331950: bpf_trace_printk: [DEBUG]: payload = GET / HTTP/1.1

    curl-6265    [001] d.s1 100477.645825: bpf_trace_printk: [DEBUG]: IPPROTO_TCP
    curl-6265    [001] d.s1 100477.645827: bpf_trace_printk: [DEBUG]: sport:35318 dport:80
    curl-6265    [001] d.s1 100477.645827: bpf_trace_printk: [DEBUG]: payload = GET /IPv6 HTTP/1.1

* View map data (in hex)
    bpftool map dump id 68
    key:
    00 00 00 00
    value:
    47 45 54 20 2f 49 50 76  36 20 48 54 54 50 2f 31
    2e 31 0d 0a 55 73 65 72  2d 41 67 65 6e 74 3a 20
    Found 1 element

* Cleanup
    ip link set dev lo xdp off

```

