#!/usr/bin/env python3

import logging
import os
import select
import socket
import struct
import fcntl

import click
import iptc
import pyroute2

import lrp
from lrp.message import RREP, DIO


class Tun:
    TUNSETIFF = 0x400454ca
    SIOCGIFINDEX = 0x8933

    IFF_TUN = 0x0001
    IFF_TAP = 0x0002

    IFNAMSIZ = 16

    _if_name_format = "tunerr%d"
    _if_nb = 0
    _if_idx = None

    def __init__(self):
        self.if_name = Tun._if_name_format % Tun._if_nb
        Tun._if_nb += 1

    def __enter__(self):
        self.fd = os.open("/dev/net/tun", os.O_RDONLY)
        ifs = fcntl.ioctl(self, Tun.TUNSETIFF,
                          struct.pack("%dsH" % Tun.IFNAMSIZ, self.if_name.encode("ascii"), Tun.IFF_TUN))
        self.if_name, _ = struct.unpack("%dsH" % Tun.IFNAMSIZ, ifs)
        self.if_name = self.if_name.decode("ascii")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0) as s:
            ifs = fcntl.ioctl(s, Tun.SIOCGIFINDEX, struct.pack("%dsi" % Tun.IFNAMSIZ, self.if_name.encode("ascii"), 0))
        _, self._if_idx = struct.unpack("%dsi" % Tun.IFNAMSIZ, ifs)
        with pyroute2.IPDB() as ipdb:
            ipdb.interfaces['tunerr0'].up().commit()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.close(self.fd)

    def fileno(self) -> int:
        """Return the tun interface file descriptor"""
        return self.fd

    def idx(self) -> int:
        """Return the tun interface index"""
        return self._if_idx

    def read(self):
        return os.read(self.fd, 1518)

    def hexdump(self, b):
        i = 0
        res = ""
        while i < len(b):
            res += "%02x" % b[i]
            i += 1
            if i % 16 == 0:
                res += "\n"
            elif i % 8 == 0:
                res += "  "
            elif i % 2 == 0:
                res += " "
        return res


class RoutesManager:
    logger = logging.getLogger("LRP")

    non_routable_mark = non_routable_table = 21
    non_routable_tun = None

    def __init__(self, interface):
        self.interface = interface

        self.routes = {}
        self._hr_destinations = []
        self._predecessors = []

    def __enter__(self):
        self._netfilter_init()
        self._netlink_init()

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def ensure_is_neighbor(self, address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            if address not in ipdb.routes:
                self.logger.info("Adding %s as neighbor" % address)
                ipdb.routes.add(dst=address, oif=self.interface,
                                scope=pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK'],
                                proto=pyroute2.netlink.rtnl.rtprotos['RTPROT_STATIC']) \
                    .commit()

    def is_neighbor(self, address) -> bool:
        """Check if neighbor is declared. Contrary to `LrpProcess.ensure_is_neighbor`, the neighbor is not added if it
        was not known."""

        if '/' not in address:
            # Suppose it is a host route
            address += "/32"

        try:
            with pyroute2.IPDB() as ipdb:
                return ipdb.routes[address]['scope'] == pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK']
        except KeyError:
            # address is unknown, it is certainly not a neighbor
            return False

    def is_successor(self, nexthop):
        try:
            return nexthop in self.routes['default']
        except KeyError:
            # No default route -> no successor at all
            return False

    def get_nexthop(self, destination=None):
        """Get a next_hop towards a `destination`. If `destination` is None, get a successor."""
        try:
            with pyroute2.IPRoute() as ipr:
                if destination is None:
                    route = ipr.get_default_routes()[0]
                else:
                    route = ipr.route('get', dst=destination)[0]
            return route.get_attr('RTA_GATEWAY')
        except pyroute2.NetlinkError:
            # No route towards the destination
            return None

    def get_mac(self, next_hop):
        with pyroute2.IPRoute() as ipr:
            return ipr.neigh("dump", dst=next_hop)[0].get_attr('NDA_LLADDR')

    def add_route(self, destination, next_hop, metric):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a route with the same
        destination/next_hop already exists, it is erased by the new one. If a route with the same destination but with
        another next_hop exists, they coexists, with their own metric. If `destination` is None, it is the default
        route."""

        # Get real destination
        if destination is None or destination == "0.0.0.0/0":
            destination = "default"
        elif '/' not in destination:
            # Suppose it is a host route
            destination += "/32"

        # Update the routing table
        try:
            self.routes[destination][next_hop] = metric
        except KeyError:
            # Destination was unknown
            self.routes[destination] = {next_hop: metric}
            self._netfilter_is_destination(destination)

        # Synchronize netlink and netfilter
        self._netlink_update_route(destination)
        if destination != "default":
            self._netfilter_is_predecessor(next_hop)

    def filter_out(self, destination, max_metric: int = None):
        """Filter out some routes, according to some constraints."""

        if destination is None:
            destination = "default"

        route = self.routes[destination]
        changed = False
        for next_hop in list(self.routes[destination].keys()):
            if route[next_hop] > max_metric:
                self.logger.info("Drop successor '%s': no more valid (metric was %d)", next_hop, route[next_hop])
                changed = True
                del route[next_hop]

        if changed:
            # Synchronize netlink
            self._netlink_update_route(destination)

    def _netfilter_init(self):
        self.logger.debug("Flush firewall rules")
        mangle_prerouting = iptc.Chain(iptc.Table(iptc.Table.MANGLE), "PREROUTING")
        mangle_prerouting.flush()

        self.logger.debug("Add firewall rule for non-routable packets")
        rule = iptc.Rule()
        rule.target = iptc.Target(rule, "MARK")
        rule.target.set_mark = "%#x" % self.non_routable_mark
        mangle_prerouting.append_rule(rule)

    def _netfilter_is_predecessor(self, next_hop):
        if next_hop not in self._predecessors:
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = self.get_mac(next_hop)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            iptc.Chain(iptc.Table(iptc.Table.MANGLE), "PREROUTING").insert_rule(rule)

    def _netfilter_is_destination(self, destination):
        if destination != "default" and destination not in self._hr_destinations:
            rule = iptc.Rule()
            rule.dst = destination
            rule.target = iptc.Target(rule, "ACCEPT")
            iptc.Chain(iptc.Table(iptc.Table.MANGLE), "PREROUTING").insert_rule(rule)

    def _netlink_init(self):
        with pyroute2.IPDB() as ipdb:
            self.logger.debug("Flush all routes & rules")
            for key in ipdb.routes.keys():
                route = ipdb.routes[key]
                self.logger.debug("Drop a route towards %s" % route['dst'])
                route.remove().commit()
            for key in list(ipdb.rules.keys()):
                if key.fwmark == self.non_routable_mark and key.fwmask == 0xffffffff:
                    self.logger.debug("Drop a rule matching the non routable mark")
                    ipdb.rules[key].remove().commit()

            self.logger.debug("Set route & rule for non-routable packets")
            ipdb.rules.add(fwmark=self.non_routable_mark, fwmask=0xffffffff, table=self.non_routable_table).commit()
            ipdb.routes.add(dst="default", table=self.non_routable_table, oif=self.non_routable_tun).commit()

    def _netlink_update_route(self, destination):
        """Must be called whenever self.routes[destination] has changed. Keep netlink synchronized with this change."""

        # If the neighbor is 'on link', (i.e. directly accessible), we do not need to change anything, the best choice
        # will always be to send the packet to itself.
        if self.is_neighbor(destination):
            return

        # Drop route if it exists
        with pyroute2.IPDB() as ipdb:
            try:
                self.logger.debug("Drop old route towards '%s'", destination)
                ipdb.routes[destination].remove().commit()
            except KeyError:
                # No such route, ok.
                pass

            # Recreate the route
            if len(self.routes[destination]) != 0:
                multipath = [{'gateway': key, 'hops': value} for key, value in self.routes[destination].items()]
                self.logger.info("Updating routing table: next hops for '%s' are %r", destination,
                                 self.routes[destination])
                ipdb.routes.add(dst=destination, multipath=multipath).commit()


class LrpProcess:
    logger = logging.getLogger("LRP")

    own_metric = 2 ** 16 - 1

    def __init__(self, interface, own_metric=None):
        self.interface = interface
        with pyroute2.IPRoute() as ip:
            try:
                self.idx = ip.link_lookup(ifname=self.interface)[0]
            except IndexError:
                raise Exception("%s: unknown interface" % self.interface)
            try:
                self.own_ip = ip.get_addr(index=self.idx)[0].get_attr('IFA_ADDRESS')
            except IndexError:
                raise Exception("%s: interface has no IP address" % self.interface)
        if own_metric is not None:
            self.own_metric = own_metric
        self._successors = {}
        self.non_routable_tun = Tun()
        self.route_manager = RoutesManager(interface=self.idx)

    def __enter__(self):
        with pyroute2.IPRoute() as ip:
            iface_address = ip.get_addr(index=self.idx)[0].get_attr('IFA_ADDRESS')
        self.logger.debug("Guess %s's address is '%s'", self.interface, iface_address)
        iface_address_as_bytes = socket.inet_aton(iface_address)
        multicast_address_as_bytes = socket.inet_aton(lrp.conf['service_multicast_address'])

        self.logger.debug("Initialize output multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.bdc_out_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.bdc_out_socket.bind((self.own_ip, 0))
        self.bdc_out_socket.connect((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize input multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.bdc_in_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.bdc_in_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                                      struct.pack("=4s4s", multicast_address_as_bytes, iface_address_as_bytes))
        self.bdc_in_socket.bind((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize unicast socket ([%s]:%d)", iface_address, lrp.conf['service_port'])
        self.uni_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.uni_socket.bind((self.own_ip, lrp.conf['service_port']))

        self.logger.debug("Create tun interface for dropped packets")
        self.non_routable_tun = self.non_routable_tun.__enter__()
        self.logger.debug("Interface name: %s" % self.non_routable_tun.if_name)

        self.route_manager.non_routable_tun = self.non_routable_tun.idx()
        self.route_manager.__enter__()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")
        self.bdc_out_socket.close()
        self.bdc_in_socket.close()
        self.uni_socket.close()

        self.logger.debug("Close %s interface", self.non_routable_tun.if_name)
        self.non_routable_tun.__exit__(exc_type, exc_val, exc_tb)

        self.route_manager.__exit__(exc_type, exc_val, exc_tb)

    def handle_routing_msg(self, msg, sender):
        if isinstance(msg, DIO):
            # Compute real route cost
            route_cost = msg.metric_value + 1

            if self.own_metric < route_cost:
                self.logger.debug("Do not use DIO: route is too bad")
                if self.own_metric + 2 < route_cost:
                    self.logger.info("Neighbor may be interested by our DIO")
                    self.broadcast_message(DIO(self.own_metric))
            else:
                self.logger.debug("Neighbor %s is an acceptable successor", sender)

                # Add route
                self.route_manager.add_route(None, sender, route_cost)

                # Update position in the DODAG
                if self.own_metric > route_cost:
                    self.logger.info("Update our metric to %d", route_cost)
                    self.own_metric = route_cost

                    self.logger.debug("Check if old successors are still usable")
                    self.route_manager.filter_out(destination=None, max_metric=self.own_metric + 1)

                    self.logger.debug("Inform neighbors that we have changed our metric")
                    self.broadcast_message(DIO(self.own_metric))

                    # TODO: we send RREP at each successor change. We should do that only sometimes.
                    successor = self.route_manager.get_nexthop(None)
                    if successor is not None:
                        self.logger.info("Refresh host route")
                        # TODO: sink address is hardcoded here
                        self.send_msg(RREP(self.own_ip, "172.18.0.1", 0), destination=successor)
                    else:
                        self.logger.error("Unable to send RREP: no more successor")

        elif isinstance(msg, RREP):
            # Real route cost: msg.hops is only the distance between the sender and the destination, without the link
            # between here and the sender
            route_cost = msg.hops + 1

            self.route_manager.add_route(msg.source, sender, route_cost)

            # Update and forward RREP
            msg.hops = route_cost
            if msg.destination == self.own_ip:
                self.logger.debug("RREP has reached its destination")
            else:
                nexthop = self.route_manager.get_nexthop(msg.destination)
                if nexthop is not None:
                    if self.route_manager.is_successor(nexthop):
                        self.logger.info("Forward %s to %s", msg.message_type, nexthop)
                        self.send_msg(msg, destination=nexthop)
                    else:
                        self.logger.error("Trying to send a RREP through %s, which is not a successor" % nexthop)
                else:
                    self.logger.error("Unable to forward %s: no route towards %s", msg.message_type, msg.destination)
        else:
            self.logger.warning("Received unknown message type: %d" % msg.message_type)

    def wait_event(self):
        self.broadcast_message(DIO(self.own_metric))
        while True:
            rr, _, _ = select.select([self.bdc_in_socket, self.uni_socket, self.non_routable_tun], [], [])
            if rr[0] is self.non_routable_tun:
                msg = self.non_routable_tun.read()
                source = socket.inet_ntoa(msg[16:20])
                destination = socket.inet_ntoa(msg[20:24])
                self.logger.warning("Drop a packet from %s to %s", source, destination)
            else:
                data, (sender, _) = rr[0].recvfrom(16)
                if sender == self.own_ip:
                    self.logger.debug("Skip a message from ourselves")
                    continue
                msg = lrp.message.Message.parse(data)
                self.logger.info("Received %s from %s", msg, sender)
                self.route_manager.ensure_is_neighbor(sender)
                self.handle_routing_msg(msg, sender)

    def send_msg(self, msg, destination):
        self.logger.info("Send %s to %s" % (msg, destination))
        self.uni_socket.sendto(msg.dump(), (destination, lrp.conf['service_port']))

    def broadcast_message(self, msg):
        self.logger.info("Send %s", msg)
        self.bdc_out_socket.send(msg.dump())


@click.command()
@click.argument("interface")
@click.argument("metric", default=2 ** 16 - 1)
def daemon(interface, metric):
    with LrpProcess(interface, metric) as lrp:
        lrp.wait_event()


if __name__ == '__main__':
    daemon()
