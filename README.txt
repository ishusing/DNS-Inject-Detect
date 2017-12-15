run command nslookup www.piazza.com
The result would have the spoofed IP if the spoofed packet wins the race

DNSInject: We sniff on the interface and when we detect a DNS request that is of our interest then we take the parameters
like source-destination port,ip, DNS transaction id, query responseand form a spoofed packet with our IP which we got either 
from the hostfile or the attacker's IP and a response is sent to the victim and hope that our packet reaches the victim 
before the legitimate response from the DNS Server

1. How to compile,
1. No compilation needed

2. Working examples of commands to run your program
2. python3 dnsinject.py -i eth0 -h hostfile.txt udp
   python3 dnsinject.py 
3. General design 
3. Explained above

4. The OS version you have tested your code on, Language and the version used.
4. Ubuntu 16.02


DNSDetect: We sniff through all the DNS packets that are received and store it in map with key being the transaction id and 
the value being a list of answer IP, TTL of the packet and the MAC address of the source.

How to check if a response is not legitimate:
Next time a DNS response with the same TX ID is received, at that time first the answer IP in both the packets is checked.
If none of the IPs in both the packets match then we do the next round of checking.
Checking for false negatives:
In the next round the TTL and the source MAC address of both the packets are compared. If either of them is different than we raise the flag.

I understand that this method does not give 100% accuracy but it will be able to detect most of the attempts.

1. How to compile
1.  No compilation needed

2. Working examples of commands to run your program
2. python3 dnsdetect.py  -r verify.pcapng udp
   python3 dnsdetect.py -i eth0 udp

3. General design 
3. Explained above

4. How do you take care of false positives( in case of dnsdetect)
4. Explained above

5. The OS version you have tested your code on, Language and the version used.
5. Ubuntu 16.02

6. Detection output for the attached pcap trace file. 
6. [2017-12-09 03:59:35.834792] DNS Poisoning Attempt
TXID 0x3c96 Request www.piazza.com
Answer 1: ['34.230.151.219', '52.45.105.168', '54.172.146.126', '54.236.180.48']
Answer 2: {'192.168.10.134'}

Caveat:

Python version = 3
The default stable build of scapy is not stable as discussed in https://piazza.com/class/j6lyorzz9qj5i3?cid=188.

References:

https://serverfault.com/questions/690391/finding-local-ip-addresses-using-pythons-stdlib-under-debian-jessie --- how to get ip of the machine I am using

https://thepacketgeek.com/scapy-p-09-scapy-and-dns/ For general scapy related help

