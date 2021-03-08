# Pinned bpf map example
* Pinning is not required to access maps from within the same program (deamon?) however, pinning is required if other userspace applications needs to interact with those maps

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

