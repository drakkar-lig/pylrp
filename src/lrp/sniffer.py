#!/usr/bin/env python3

import click
from scapy.all import IP, UDP, sniff

import lrp.message


@click.command()
@click.argument("interface")
def sniff(interface: str):
    """Sniff and print LRP packets"""

    def dump(pkt):
        lrp_payload = pkt[UDP].payload
        print("[%s]:%d -> [%s]:%s, %s" % (
            pkt[IP].src, pkt[UDP].sport,
            pkt[IP].dst, pkt[UDP].dport,
            lrp.message.Message.parse(bytes(lrp_payload))))

    sniff(iface=interface, prn=dump, filter="udp port 6666", store=0)


if __name__ == '__main__':
    sniff()
