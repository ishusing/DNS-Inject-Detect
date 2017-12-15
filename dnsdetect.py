import getopt
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
from threading import Thread
import datetime
from multiprocessing  import Queue
pkt_q = Queue()
tx_id_ip = {}

def is_valid_ip(s):
    a = s.split('.')
    if len(a) != 4:
#checks if there are 4 sets of 8 bits
        return False
    for byte_val in a:
        if not byte_val.isdigit():
            return False
        int_val = int(byte_val)
#checks if it a valid 8 bit number
        if int_val < 0 or int_val > 255:
            return False
    return True

def threaded_function(current_ips,stored_ips,id,domain,timeM):
    union = set(current_ips).union(set(stored_ips))
    # t = time.gmtime(int(timeM))
    ts = datetime.datetime.fromtimestamp(timeM).strftime('%Y-%m-%d %H:%M:%S.%f')
    # time = getTime()
    print("[%s] DNS Poisoning Attempt" % ts)
    hex_id = hex(id)
    print("TXID",hex_id,"Request",str(domain))
    print("Answer 1: " + ', '.join(current_ips))#str(current_ips))
    print("Answer 2: " + ', '.join(stored_ips))#str(stored_ips))
    print("\n")
    # for ip in union:
    #     print(ip)
        # sleep(1)


def detect_packets(pkt):
	if (DNS in pkt and
            pkt[DNS].ancount >= 1):
            #print(pkt.time)
            dns =pkt[DNS]
            id= dns.id
            ttl= pkt[IP].ttl
            src_mac = pkt.src
            current_ips = []
            for i in range(dns.ancount):
                dnsrr = dns.an[i]
                # print(type(dnsrr.rdata))
                if not is_valid_ip(str(dnsrr.rdata)):
                    continue
                current_ips.append(dnsrr.rdata)
            stored_ips = []
            stored_ttl = 0;
            stored_mac = '';
            if tx_id_ip.get(id) != None:
                stored_ips = tx_id_ip.get(id)[0]
                stored_ttl = tx_id_ip.get(id)[1]
                stored_mac = tx_id_ip.get(id)[2]
            intersection = set(current_ips).intersection(stored_ips)
            union = set(current_ips).union(stored_ips)
            tx_id_ip[id] = [union,ttl,src_mac]
            if(len(stored_ips) != 0 and len(intersection) == 0):
                # print("Possible Attack found, checking reverse lookup")
                domain = pkt[DNS].qd.qname.decode('ASCII');
                domain = domain[:len(domain) - 1]
                if(stored_mac != src_mac or stored_ttl != ttl):

                    thread = Thread(target=threaded_function, kwargs={'current_ips': current_ips,'stored_ips': stored_ips,
                                                                  'id':id,'domain':domain,'timeM':pkt.time})
                    thread.start()

                tx_id_ip.pop(id)


#print('ARGV      :', sys.argv[1:])
interface = 'ens33'
tracefile = 'dnsinject.pcapng'
tracefile_present = False
bpf = ''
opt_index = 0
options, remainder = getopt.getopt(sys.argv[1:], 'i:r:')
#print('OPTIONS   :', options)
#print('Remainder: ', remainder)

for rem in remainder:
	bpf = bpf + ' ' + rem
for opt, arg in options:
    if opt in ('-i'):
        interface = arg
    elif opt in ('-r'):
        tracefile = arg
        tracefile_present = True
# print 'interface   :', interface
# print 'tracefile   :', tracefile
# print 'tracefile_present    :', tracefile_present
# print 'BPF    :', bpf

if tracefile_present:
    # packets = rdpcap(tracefile)
    # for packet in packets:
	 #    detect_packets(packet)
    sniff(offline=tracefile,store=0, prn=detect_packets)
else:
    # sniff(filter=bpf, iface=interface, store=0, prn=detect_packets)
    sniff(filter=bpf, iface=interface, store=0, prn=detect_packets)

