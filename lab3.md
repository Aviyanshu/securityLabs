# Lab 3

##Intercepting Communications

* Level 1
```bash
nc 10.0.0.3 31337
```

* Level 2
```bash
nc -l 31337
```

* Level 3
```bash
nmap -p 31337 10.0.0.0/24

nc 10.0.0.114 31337
```

* Level 5
```bash
tcpdump -X -i any port 31337
```

* Level 10
```python
>>from scapy.all import*

>>> pkt = Ether(src="5a:9e:84:98:70:09") / IP(src="10.0.0.2", dst="10.0.0.3") /
...: TCP(sport=31337, dport=31337, seq=31337, ack=31337, flags="APRSF")
>>> sendp(pkt, iface="eth0")
WARNING: No route found (no default route?)
.
Sent 1 packets.
```