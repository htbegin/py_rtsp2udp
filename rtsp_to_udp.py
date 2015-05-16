#!/usr/bin/env python

import os
import sys
from collections import namedtuple
from optparse import OptionParser
import logging

# Disable scapy runtime warning
# "WARNING: No route found for IPv6 destination :: (no default route?)"
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
del logging
from scapy.all import *

sp_fields = ("saddr", "sport", "daddr", "dport")
class SockPair(namedtuple("SockPair", sp_fields)):
    def __str__(self):
        def _astr(addr):
            return addr if addr is not None else "all"
        def _pstr(port):
            return "%-5u" % port if port is not None else "*"
        return "%s:%s -> %s:%s" % (_astr(self.saddr), _pstr(self.sport),
                                   _astr(self.daddr), _pstr(self.dport))

    def match_template(self, tmpt):
        matched = True
        for f in sp_fields:
            self_val = getattr(self, f)
            tmpt_val = getattr(tmpt, f)
            if self_val != tmpt_val and tmpt_val is not None:
                matched = False
                break
        return matched

    def cname(self):
        return "%s_%u_to_%s_%u" % (self.saddr, self.sport, self.daddr, self.dport)

def pkt_has_tcp_payload(p):
    # IP data diagram len - IP hdr len - TCP hdr len
    load_len = p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
    return 0 < load_len

def filtered_tcp_pkt_load(pkts, tmpt_sk_pair):
    used_sk_pair = set()
    for p in pkts:
        if TCP in p:
            pkt_sk_pair = SockPair(p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport)
            pkt_matched = pkt_sk_pair.match_template(tmpt_sk_pair)
            action = "Got" if pkt_matched else "Filter"
            if pkt_sk_pair not in used_sk_pair:
                print "%-6s TCP flow [%s]" % (action, str(pkt_sk_pair))
                used_sk_pair.add(pkt_sk_pair)

            if pkt_matched and pkt_has_tcp_payload(p):
                yield pkt_sk_pair, p[TCP].load

def gen_udp_load_list(load_list):
    udp_load_list = []

    load_array = "".join(load_list)

    idx = 0
    chan_list = [0, 2]
    max_sz = 64 << 10
    max_idx = len(load_array) - 1
    while True:
        if max_idx < idx + 3:
            break

        if "$" == load_array[idx]:
            start, end = idx + 1, idx + 2
            chan = struct.unpack("B", load_array[start:end])[0]

            start, end = idx + 2, idx + 4
            sz = struct.unpack(">H", load_array[start:end])[0]

            if chan in chan_list and sz <= max_sz:
                start, end = idx + 4, idx + 4 + sz
                if end <= max_idx + 1:
                    #print "Got udp pkt with chan %u len %u" % (chan, sz)
                    udp_load_list.append(load_array[start:end])
                    idx = end
                    continue

        idx += 1

    return udp_load_list

def rtsp_to_udp(fname, sk_pair):
    pkts = rdpcap(fname)

    load_list_map = {}
    for pkt_sk_pair, load in filtered_tcp_pkt_load(pkts, sk_pair):
        load_list_map.setdefault(pkt_sk_pair, []).append(load)

    if not load_list_map:
        print "No valid pkt for filter [%s]" % str(sk_pair)
        return

    full_fpath = os.path.abspath(fname)
    pcap_dir = os.path.dirname(full_fpath)
    name_prefix, ext = os.path.splitext(os.path.basename(full_fpath))

    for idx, (pkt_sk_pair, load_list) in enumerate(load_list_map.iteritems()):
        udp_load_list = gen_udp_load_list(load_list)

        udp_pkt_list = []
        for load in udp_load_list:
            udp_pkt = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00")/IP()/ \
                      UDP(dport=6000+idx, sport=7000+idx)/load
            udp_pkt_list.append(udp_pkt)

        if udp_pkt_list:
            if len(load_list_map) == 1:
                uniq_name = "udp"
            else:
                uniq_name = "udp_%s" % pkt_sk_pair.cname()
            udp_fname = os.path.join(pcap_dir, "%s_%s%s" % (uniq_name, name_prefix, ext))
            print "In: %s, Out: %s" % (fname, udp_fname)
            wrpcap(udp_fname, udp_pkt_list)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-s", "--sport", dest="sport", type="int",
                      help="tcp source port")
    parser.add_option("-d", "--dport", dest="dport", type="int",
                      help="tcp destination port")
    parser.add_option("-f", "--saddr", dest="saddr", type="string",
                      help="tcp source addr")
    parser.add_option("-t", "--daddr", dest="daddr", type="string",
                      help="tcp destination addr")
    parser.add_option("-i", "--input", dest="pcap_fname", help="the file name of pcap")

    options, _ = parser.parse_args()
    if options.pcap_fname is None:
        parser.print_help()
        sys.exit(1)

    rtsp_to_udp(options.pcap_fname,
                SockPair(options.saddr, options.sport, options.daddr, options.dport))
    sys.exit(0)

