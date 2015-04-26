#!/usr/bin/env python

import os
import sys
from optparse import OptionParser
import logging

# Disable scapy runtime warning
# "WARNING: No route found for IPv6 destination :: (no default route?)"
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
del logging
from scapy.all import *

def is_expected_tcp_pkt(p, s_d_port, used_s_d_port):
    sport, dport = s_d_port

    pkt_sport, pkt_dport = p[TCP].sport, p[TCP].dport
    exp_pkt_sport = sport if sport is not None else pkt_sport
    exp_pkt_dport = dport if dport is not None else pkt_dport

    port_matched = False
    if pkt_sport == exp_pkt_sport and pkt_dport == exp_pkt_dport:
        port_matched = True

    action = "Got" if port_matched else "Filter"
    if (pkt_sport, pkt_dport) not in used_s_d_port:
        print "%-6s TCP flow (%-5u -> %5u)" % (action, pkt_sport, pkt_dport)
        used_s_d_port.add((pkt_sport, pkt_dport))

    is_expected = False
    # IP data diagram len - IP hdr len - TCP hdr len
    load_len = p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
    if port_matched and 0 < load_len:
        is_expected = True

    return is_expected

def all_tcp_pkt_load(pkts, s_d_port):
    used_s_d_port = set()
    for p in pkts:
        if TCP in p and is_expected_tcp_pkt(p, s_d_port, used_s_d_port):
            yield p[TCP].load

def port_pair_to_filter_str(sport, dport):
    cond = []
    if sport is not None:
        cond.append("sport == %d" % sport)
    if dport is not None:
        cond.append("dport == %d" % dport)

    if cond:
        return " and ".join(cond)
    else:
        return "none"

def rtsp_to_udp(fname, s_d_port):
    pkts = rdpcap(fname)

    load_list = []
    for l in all_tcp_pkt_load(pkts, s_d_port):
        load_list.append(l)

    if not load_list:
        print "No valid pkt for filter (%s)" % port_pair_to_filter_str(*s_d_port)
        return

    load_array = "".join(load_list)

    idx = 0
    chan_list = [0, 2]
    max_sz = 64 << 10
    max_idx = len(load_array) - 1
    udp_load_list = []
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

    udp_pkt_list = []
    for load in udp_load_list:
        udp_pkt = Ether(dst="00:00:00:00:00:00", src="00:00:00:00:00:00")/IP()/ \
                  UDP(dport=6000, sport=7000)/load
        udp_pkt_list.append(udp_pkt)

    if udp_pkt_list:
        name_prefix, ext = os.path.splitext(fname)
        udp_fname = "udp_%s%s" % (name_prefix, ext)
        print "In: %s, Out: %s" % (fname, udp_fname)
        wrpcap(udp_fname, udp_pkt_list)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-s", "--sport", dest="sport", type="int",
                      help="tcp source port")
    parser.add_option("-d", "--dport", dest="dport", type="int",
                      help="tcp destination port")
    parser.add_option("-f", "--file", dest="pcap_fname", help="the file name of pcap")

    options, _ = parser.parse_args()
    if options.pcap_fname is None:
        parser.print_help()
        sys.exit(1)

    rtsp_to_udp(options.pcap_fname, (options.sport, options.dport))
    sys.exit(0)

