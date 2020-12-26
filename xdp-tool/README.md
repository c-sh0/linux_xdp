# xdp-tool
Simple program to manage XDP programs

## Description
Modified copy of `basic01-xdp-pass/xdp_pass_user.c` from the [xdp-tutorial](https://github.com/xdp-project/xdp-tutorial) repository.

```
Usage: ./xdp-tool [options]

DOCUMENTATION:
 Simple program to manage XDP programs

Required options:
 -d, --dev <ifname>         Operate on device <ifname>

Other options:
 -h, --help                 Show help
 -o, --object               Path to XDP object file
 -S, --skb-mode             Install XDP program in SKB (AKA generic) mode
 -N, --native-mode          Install XDP program in native mode
 -A, --auto-mode            Auto-detect SKB or native mode
 -F, --force                Force install, replacing existing program on interface
 -U, --unload               Unload XDP program instead of loading
```
## Notes
You may need to increase max locked memory user limit
``
ulimit -l unlimited
``

## TODO
- Additional modifications

