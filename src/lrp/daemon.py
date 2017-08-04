#!/usr/bin/env python3

import logging
import select
import socket
import struct

import click
import iptc
import netfilterqueue
import pyroute2

import lrp
from lrp.message import RREP, DIO


class RoutesManager:
    logger = logging.getLogger("LRP")

    def __init__(self, lrpp):
        """lrpp: the LRP process"""
        self.lrpp = lrpp

        self.routes = {}
        self._hr_destinations = {}
        self._predecessors = {}
        self._netfilter_non_routable_chain = None

    def __enter__(self):
        self._netfilter_init()
        self._netlink_init()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._netlink_clean()
        self._netfilter_clean()

    def ensure_is_neighbor(self, address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            if address not in ipdb.routes:
                self.logger.info("Adding %s as neighbor" % address)
                ipdb.routes.add(dst=address, oif=self.lrpp.idx,
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
        # Check the routes that LRP knows
        try:
            if nexthop in self.routes['default']:
                return True
        except KeyError:
            # No default route known by LRP. Continue...
            pass
        # Check if the system knows one default route we don't know
        with pyroute2.IPDB() as ipdb:
            for route in ipdb.routes.filter({'dst': "default"}):
                if nexthop == route['route']['gateway']:
                    return True
                for nh in route['route']['multipath']:
                    if nexthop == nh['gateway']:
                        return True
        # Unable to find this neighbor in any default route. It is not a successor.
        return False

    def get_nexthop(self, destination=None):
        """Get a next_hop towards a `destination`. If `destination` is None, get a successor."""
        try:
            with pyroute2.IPRoute() as ipr:
                if destination is None:
                    route = ipr.get_default_routes()[0]
                else:
                    route = ipr.route('get', dst=destination)[0]
                nexthop = route.get_attr('RTA_GATEWAY')
                if nexthop is not None:
                    # We have a route towards this destination
                    return nexthop
                oif = route.get_attr('RTA_OIF')
                if oif is not None:
                    # The destination is on link, return itself
                    return destination
        except pyroute2.NetlinkError:
            # No route towards the destination
            return None

    def get_mac(self, next_hop):
        with pyroute2.IPRoute() as ipr:
            return ipr.neigh("dump", dst=next_hop)[0].get_attr('NDA_LLADDR').upper()

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
        self._netfilter_non_routable_chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "FORWARD")
        self.logger.debug("Flush firewall rules")
        self._netfilter_non_routable_chain.flush()

        self.logger.debug("Add firewall rule for non-routable packets")
        self._non_routable_rule = iptc.Rule()
        self._non_routable_rule.target = iptc.Target(self._non_routable_rule, "NFQUEUE")
        self._non_routable_rule.target.queue_num = str(self.lrpp.non_routable_queue_nb)
        self._netfilter_non_routable_chain.append_rule(self._non_routable_rule)

    def _netfilter_clean(self):
        # Drop firewall rules for packets following a host route
        for rule in self._hr_destinations.values():
            self.logger.debug("Clean firewall rule towards %s", rule.dst)
            self._netfilter_non_routable_chain.delete_rule(rule)
        self._hr_destinations.clear()

        # Drop firewall rules for packets coming from a predecessor
        for rule in self._predecessors.values():
            self.logger.debug("Clean firewall rule through %s", rule.matches[0].mac_source)
            self._netfilter_non_routable_chain.delete_rule(rule)
        self._predecessors.clear()

        # Drop non-routable packets detection
        self.logger.debug("Clean firewall rule for non-routable packets")
        self._netfilter_non_routable_chain.delete_rule(self._non_routable_rule)
        self._non_routable_rule = None

    def _netfilter_is_predecessor(self, next_hop):
        if next_hop not in self._predecessors:
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = self.get_mac(next_hop)
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            self._netfilter_non_routable_chain.insert_rule(rule)
            self._predecessors[next_hop] = rule

    def _netfilter_is_destination(self, destination):
        if destination != "default" and destination not in self._hr_destinations:
            rule = iptc.Rule()
            rule.dst = destination
            rule.target = iptc.Target(rule, "ACCEPT")
            self._netfilter_non_routable_chain.insert_rule(rule)
            self._hr_destinations[destination] = rule

    def _netlink_init(self):
        pass

    def _netlink_clean(self):
        with pyroute2.IPDB() as ipdb:
            # Drop all routes inserted by LRP in the kernel routing table
            for destination in self.routes:
                self.logger.debug("Clean route towards %s", destination)
                ipdb.routes[destination].remove().commit()
            self.routes.clear()

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
    non_routable_queue_nb = 7

    def __init__(self, interface, own_metric=None, is_sink=False):
        self.interface = interface
        self.is_sink = is_sink
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
        self.dropped_queue = netfilterqueue.NetfilterQueue()
        self.route_manager = RoutesManager(self)

        if self.is_sink:
            self.sink = self.own_ip
        else:
            self.sink = None

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

        def queue_packet_handler(packet):
            payload = packet.get_payload()
            source = socket.inet_ntoa(payload[12:16])
            destination = socket.inet_ntoa(payload[16:20])
            sender = ":".join(["%02x" % b for b in packet.get_hw()[0:6]])
            self.handle_non_routable_packet(source, destination, sender)
            packet.drop()

        self.logger.debug("Bind netfilter non-routable packets to queue %d", self.non_routable_queue_nb)
        self.dropped_queue.bind(self.non_routable_queue_nb, queue_packet_handler)
        self._dropped_queue_socket = socket.fromfd(self.dropped_queue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        self._dropped_queue_socket.setblocking(False)

        self.route_manager.__enter__()

        self.logger.debug("LRP%s process started" % " sink" if self.is_sink else "")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")
        self.bdc_out_socket.close()
        self.bdc_in_socket.close()
        self.uni_socket.close()

        self._dropped_queue_socket.close()
        self.dropped_queue.unbind()

        self.route_manager.__exit__(exc_type, exc_val, exc_tb)

    def handle_routing_msg(self, msg, sender):
        if isinstance(msg, DIO):
            # Compute real route cost
            route_cost = msg.metric_value + 1

            # Check if this sink is supported
            if msg.sink is not None and self.sink is not None and msg.sink != self.sink:
                self.logger.warning("Drop DIO: not the same sink (many sinks are not handled now)")

            elif msg.sink is None or self.own_metric < route_cost:
                self.logger.debug("Do not use DIO: route is too bad")
                if self.own_metric + 2 < route_cost:
                    self.logger.info("Neighbor may be interested by our DIO")
                    self.broadcast_message(DIO(self.own_metric, sink=self.sink))

            else:
                self.logger.debug("Neighbor %s is an acceptable successor", sender)
                was_already_successor = self.route_manager.is_successor(sender)

                # Add route
                self.route_manager.add_route(None, sender, route_cost)

                # Update position in the DODAG
                if self.own_metric > route_cost:
                    self.logger.info("Update our metric to %d", route_cost)
                    self.own_metric = route_cost

                    if self.sink != msg.sink:
                        assert self.sink is None, \
                            "Trying to change the sink we are attached to (%s -> %s)" % (self.sink, msg.sink)
                        self.logger.info("Update our sink to %s", msg.sink)
                        self.sink = msg.sink

                    self.logger.debug("Check if old successors are still usable")
                    self.route_manager.filter_out(destination=None, max_metric=self.own_metric + 1)

                    self.logger.debug("Inform neighbors that we have changed our metric")
                    self.broadcast_message(DIO(self.own_metric, sink=self.sink))

                if not was_already_successor:
                    # This neighbor does not know us as predecessor. Send RREP
                    self.logger.info("Create host route through %s" % sender)
                    self.send_msg(RREP(self.own_ip, self.sink, 0), destination=sender)

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
                    assert self.route_manager.is_successor(nexthop), \
                        "Trying to send a RREP through %s, which is not a successor (forbidden!)" % nexthop
                    self.logger.info("Forward %s to %s", msg.message_type, nexthop)
                    self.send_msg(msg, destination=nexthop)
                else:
                    self.logger.error("Unable to forward %s: no route towards %s", msg.message_type, msg.destination)
        else:
            self.logger.warning("Received unknown message type: %d" % msg.message_type)

    def handle_non_routable_packet(self, source, destination, sender):
        self.logger.warning("Drop a non-routable packet: %s --(%s)--> %s", source, sender, destination)

    def wait_event(self):
        self.broadcast_message(DIO(self.own_metric, sink=self.sink))
        while True:
            rr, _, _ = select.select([self.bdc_in_socket, self.uni_socket, self._dropped_queue_socket], [], [])
            if rr[0] is self._dropped_queue_socket:
                self.dropped_queue.run(block=False)
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
@click.option("--sink/--no-sink")
def daemon(interface, metric, sink=False):
    with LrpProcess(interface, metric, is_sink=sink) as lrp:
        lrp.wait_event()


if __name__ == '__main__':
    daemon()
