# port_ticker
Keep track of connection attempts being made to destination port (listening or not). If a subsequent connection is made from the same source address to a different destination port, log it. 
 
## Tested on
* CentOS 7.9.2009

## What it does
For all incoming packets:
* Count the number of times a source ip has changed form it's last recorded destination port

 Assuming you maintain a strict access policy, if there is a high deviation from a single ip connecting to many different ports, log it. It "could" be an indication of nefarious activity (ie: port scans, port knocking, malware, etc..). This same functionality could be achieved using `nf_conntrack` or a firewall (`iptables`) and running some kind of log analyzer or something but, i was curious as to what the level of effort would be just to track the destination port changes using XDP.

## What it doesn't do
* Take actions to block traffic
* DPI (Deep Packet Inspection)
* Track connection states

While these features can be implemented very easily, this was just a weekend feasibility exercise. 
- This program would probably be most useful for systems intended for a very specific purpose. 
- This has not been tested for performance or accuracy
- More info? review code comments
- You can do what ever you want with this code. (WTFPL) ;)

## Usage
```
Usage: ticker_ctl [OPTIONS]

 Options:

  -d, --dev <device>         Use <device> (required)
  -S, --skb-mode             Use SKB mode (default: try driver mode)
  -i, --ignore <src_ip>      Ignore all <src_ip> packets
  -I, --icmp-enable [0,1]    Disable/Enable icmp responses (default disabled: 0)
  -t, --threshold <n>        Threshold to record the number of times a src_ip changed dest_port (default: 20)
  -l, --list                 List source ip and port change counters
  -r, --remove               Remove program from <device>

 Examples:

    ticker_ctl -d eth0 -S               :- Install program on eth0 SKB mode
    ticker_ctl -d eth0 -i 192.168.1.20  :- Add ip 192.168.1.20 to the ignore list (return traffic from any outbound connections?)
    ticker_ctl -d eth0 -I 1             :- Enable ICMP responses
    ticker_ctl -d eth0 -t 200           :- Increase tracking threshold
    ticker_ctl -d eth0 -l               :- List logged source ip's whos ports have changed > threshold
```
## Example
```
* Load (localhost)
    ./ticker_ctl -d lo -S

* Enable ICMP
    ./ticker_ctl -d lo -I 1

* Port scan 
    nmap 127.0.0.1

* Simple report
    ./ticker_ctl -d lo -l
    Report:

    -------------------------------------
    Source IP       |  Change count
    -------------------------------------
    127.0.0.1       |  2122
```

## References
* Inspired by https://github.com/hyp3rlinx/Recon-Informer
