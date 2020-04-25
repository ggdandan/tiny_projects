#!/usr/bin/env python3

import logging
import os
import sys

from scapy.all import rdpcap
from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, TCP
from scapy.packet import split_layers

import struct
import matplotlib.pyplot as plt

LOG = logging.getLogger("main")


def printHis(rcode):
    plt.bar(range(len(rcode)), list(rcode.values()), align='center')
    plt.xticks(range(len(rcode)), list(rcode.keys()))
    plt.xlabel("RCODE")
    plt.ylabel("Count")
    plt.title("Histogram of RCODE")
    plt.show()


def parsePartialDNS(rawload, proto):
    # proto udp = 17, tcp = 6
    offset = 0
    # Skip 2 Bytes of len for TCP.
    if proto == 6:
        offset += 2
        length, = struct.unpack_from("!B", rawload, offset)
    dnsparsing = struct.Struct("!6H")
    id, flag, qd, an, ns, ar = dnsparsing.unpack_from(rawload, offset)
    domain = []
    # Skip header.
    offset += 12
    # Get domain.
    while True:
        labelLen = struct.unpack_from("!B", rawload, offset)
        LOG.debug(labelLen[0])
        if labelLen[0] == 0:
            break
        st2 = struct.Struct("!" + str(labelLen[0]) + "s")
        offset += 1
        domain.append(st2.unpack_from(rawload, offset)[0].decode("utf-8"))
        offset += labelLen[0]
    d = ".".join(domain)
    return flag, id, d, an

def main():
    if len(sys.argv) < 2:
        raise ValueError("Usage: %s <pcap file>" % os.path.basename(sys.argv[0]))

    # Use scapy for IP/UDP/TCP parsing only - not for parsing DNS
    split_layers(UDP, DNS)
    split_layers(TCP, DNS)

    pcap_filename = sys.argv[1]
    packets = rdpcap(pcap_filename)

    LOG.info("Loaded %s: %r", pcap_filename, packets)

    #LOG.debug("%s", packets[1667].show())
    #parsePartialDNS(packets[2589].load, packets[2589].proto)

    dns_num = 0
    total = 0
    rcode_catagory = {}
    sizelist = []
    total_size = 0
    roundtrip = {}
    domainDic = {}
    maxAn = 0

    for pkt in packets:
        total += 1
        # Packet size = IP size + 14 frame size
        if hasattr(pkt, 'len'):
            # frame size = 14 Bytes
            sizelist.append(pkt.len + 14)
            total_size += pkt.len + 14
        # DNS payload part.
        if hasattr(pkt, 'load'):
            # DNS port = 53
            if (hasattr(pkt, 'dport') and pkt.dport == 53) or \
                    (hasattr(pkt, 'sport') and pkt.sport == 53):
                dns_num += 1
                # UDP & TCP proto No.
                if pkt.proto == 17 or pkt.proto == 6:
                    flag, id, d, an = parsePartialDNS(pkt.load, pkt.proto)
                    rcode = flag & 0xF
                    qr = flag & 0x8000
                    if qr :
                        maxAn = max(maxAn, an)
                    # RCODE statistic.
                    if rcode not in rcode_catagory:
                        rcode_catagory[rcode] = 0
                    else:
                        rcode_catagory[rcode] += 1
                    # Latency statistic.
                    time = pkt.time
                    if id not in roundtrip:
                        roundtrip[id] = time
                    else:
                        roundtrip[id] = abs(roundtrip[id] - time)
                    # LOG.info("%s  %s", hex(id), total)
                    # Domain statistic.
                    if d not in domainDic:
                        domainDic[d] = 1
                    else:
                        domainDic[d] += 1

        LOG.debug("Visiting packet: %r", pkt)
        # TODO: Your code can start here.

    sorted_domain = sorted(domainDic.items(), key=lambda x: x[1])

    sizelist.sort()
    l = len(sizelist)
    a = int(l / 2)
    b = int((l - 1) / 2)
    median = (sizelist[a] + sizelist[b]) / 2
    LOG.info("The number of DNS is %s", dns_num)
    LOG.info("The most number of RRs is %s", maxAn)
    LOG.info("Average packet size : %.3f Bytes", total_size / l)
    LOG.info("Median packet size : %s Bytes", median)

    n = 1
    while n < 6:
        LOG.info("top " + str(n) + " frequency domain : %s", sorted_domain.pop())
        n += 1

    total_latency = []
    for k, v in roundtrip.items():
        total_latency.append(v)

    LOG.info("Average Latency : %.3fs", sum(total_latency) / len(roundtrip))

    total_latency.sort()
    latency95_idx = int(len(total_latency) * 0.95)
    LOG.info("95Latency: %.3fs", total_latency[latency95_idx])

    printHis(rcode_catagory)

    LOG.info("Done.")


if __name__ == "__main__":
    logging.basicConfig(
        format="[%(funcName)s] %(message)s",
        level=logging.INFO)
    main()
