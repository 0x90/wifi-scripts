# WiFi Scripts

All WiFi moved to https://github.com/0x90/wifi-arsenal

Python scripts and tools for WiFi.

## Dummy 802.11 sniffer

```python
from scapy.all import *

sniff(iface='eth0', 
    prn=lambda x: 
    x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\tDot11Beacon.cap%}"))
```
