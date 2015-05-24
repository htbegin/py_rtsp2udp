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

GOT_SEQ_KEY, MISSED_SEQ_KEY, IGNORED_SEQ_KEY = "got", "missed", "ignored"
MIN_SEQ_IDX, EXP_SEQ_IDX = range(2)
APPEND, INSERT, IGNORE = range(3)

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
                yield pkt_sk_pair, p[TCP].seq, p[TCP].load

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

# True if a after b
def is_u32_seq_after(a, b):
    def two_s_complement(n):
        s = 31
        w = 2 << s
        m = w - 1
        return (-w * (n >> s) + (n & m))

    return two_s_complement(b) - two_s_complement(a) < 0

def add_missed_seq(start_seq, end_seq, seq_range):
    action, arg = IGNORE, None

    found = False
    missed_range = seq_range[MISSED_SEQ_KEY]
    for idx, (start, end, pos) in enumerate(missed_range):
        if start <= start_seq and end_seq <= end:
            if start == start_seq and end_seq == end:
                del missed_range[idx]
            else:
                new_entry_idx = idx
                if start < start_seq:
                    # replace the origin missed entry
                    # insert the load before [start_seq, end_seq) => pos
                    missed_range[new_entry_idx] = (start, start_seq, pos)
                    new_entry_idx += 1
                if end_seq < end:
                    # insert the lod after [start_seq, end_seq) => pos + 1
                    # replace or insert after the missed entry
                    new_entry = (end_seq, end, pos + 1)
                    if new_entry_idx == idx:
                        missed_range[new_entry_idx] = new_entry
                    else:
                        missed_range.insert(new_entry_idx, new_entry)
            found, action, arg = True, INSERT, pos
            break

    if not found:

        min_seq = got_range[MIN_SEQ_IDX]
        if min_seq == end_seq or is_u32_seq_after(min_seq, end_seq):
            print "Prepend tcp range [%u, %u) (min %u) on %s" % \
                  (start_seq, end_seq, min_seq, str(sk_pair))

            if min_seq != end_seq:
                missed_range.insert(0, (end_seq, min_seq, 1))
            got_range[MIN_SEQ_IDX] = start_seq

            action = INSERT, 0
        else:
            ignored_range = seq_range[IGNORED_SEQ_KEY]
            ignored_range.append((start_seq, end_seq))

    return action, arg

# [start, end)
def update_seq_range(sk_pair, start_seq, end_seq,
                     seq_range, next_pos):
    action, arg = APPEND, None

    cur_range = [start_seq, end_seq]
    got_range = seq_range.setdefault(GOT_SEQ_KEY, cur_range)
    missed_range = seq_range.setdefault(MISSED_SEQ_KEY, [])
    seq_range.setdefault(IGNORED_SEQ_KEY, [])

    if got_range != cur_range:
        exp_seq = got_range[EXP_SEQ_IDX]

        # the most likely case
        if start_seq == exp_seq:
            got_range[EXP_SEQ_IDX] = end_seq
        elif is_u32_seq_after(start_seq, exp_seq):
            got_range[EXP_SEQ_IDX] = end_seq
            missed_range.append([exp_seq, start_seq, next_pos])
        else:
            # No need to update the expected seq
            action, arg = add_missed_seq(start_seq, end_seq, seq_range)

    return action, arg

def dump_ignored_seq_range(sk_pair, ignored_range):
    if ignored_range:
        print "Ignored seq range (total %u) on %s:" % (len(ignored_range), str(sk_pair))
        for idx, (start, end) in enumerate(ignored_range):
            print " #%-10u [%10u, %10u)" % (idx + 1, start, end)

def dump_load_seq_list(sk_pair, seq_list):
    if seq_list:
        print "Used seq range (total %u) on %s:" % (len(seq_list), str(sk_pair))
        for idx, (start, end) in enumerate(seq_list):
            print " #%-10u [%10u, %10u)" % (idx + 1, start, end)

def rtsp_to_udp(fname, sk_pair):
    TCP_SEQ_MASK = (2 << 32) - 1
    pkts = rdpcap(fname)

    load_list_map = {}
    seq_range_map = {}
    load_seq_list_map = {}
    for pkt_sk_pair, seq, load in filtered_tcp_pkt_load(pkts, sk_pair):
        load_list = load_list_map.setdefault(pkt_sk_pair, [])
        seq_range = seq_range_map.setdefault(pkt_sk_pair, {})
        load_seq_list = load_seq_list_map.setdefault(pkt_sk_pair, [])

        start_seq, end_seq = seq, (seq + len(load)) & TCP_SEQ_MASK
        action, arg = update_seq_range(pkt_sk_pair, start_seq, end_seq,
                                       seq_range, len(load_list))
        if APPEND == action:
            load_list.append(load)
            load_seq_list.append((start_seq, end_seq))
        elif INSERT == action:
            load_list.insert(arg, load)
            load_seq_list.insert(arg, (start_seq, end_seq))
        elif IGNORE == action:
            pass

    if not load_list_map:
        print "No valid pkt for filter [%s]" % str(sk_pair)
        return

    full_fpath = os.path.abspath(fname)
    pcap_dir = os.path.dirname(full_fpath)
    name_prefix, ext = os.path.splitext(os.path.basename(full_fpath))

    for idx, (pkt_sk_pair, load_list) in enumerate(load_list_map.iteritems()):
        dump_ignored_seq_range(pkt_sk_pair, seq_range_map[pkt_sk_pair][IGNORED_SEQ_KEY])

        if options.verbose:
            dump_load_seq_list(pkt_sk_pair, load_seq_list_map[pkt_sk_pair])

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
    parser.add_option("-v", "--verbose", dest="verbose", default=False, action="store_true",
                      help="more debug info")

    options, _ = parser.parse_args()
    if options.pcap_fname is None:
        parser.print_help()
        sys.exit(1)

    rtsp_to_udp(options.pcap_fname,
                SockPair(options.saddr, options.sport, options.daddr, options.dport))
    sys.exit(0)

