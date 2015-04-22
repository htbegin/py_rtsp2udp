#!/usr/bin/env python

import os
import sys
from scapy.all import *

def all_tcp_pkt_load(pkts):
    for p in pkts:
        if TCP in p:
            # IP data diagram len - IP hdr len - TCP hdr len
            load_len = p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
            if 0 < load_len:
                yield p[TCP].load

def rtsp_to_udp(fname):
    pkts = rdpcap(fname)

    load_list = []
    for l in all_tcp_pkt_load(pkts):
        load_list.append(l)

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
        print "%s -> %s" % (fname, udp_fname)
        wrpcap(udp_fname, udp_pkt_list)

if __name__ == "__main__":
    ret = 0
    if 1 < len(sys.argv):
        for fname in sys.argv[1:]:
            rtsp_to_udp(fname)
    else:
        sys.stderr.write("Usage: %s pcap_files..." % sys.argv[0])
        ret = 1

    sys.exit(ret)

