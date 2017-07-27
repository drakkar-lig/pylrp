#!/usr/bin/env python3

import logging
import select
import socket
import struct

import click
import pyroute2

import lrp
from lrp.message import RREP, DIO


class RoutesManager:
    logger = logging.getLogger("LRP")

    def __init__(self, interface):
        self.routes = {}
        self.interface = interface

        self._flush_routes()

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

    def _update_route(self, destination):
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
                self.logger.info("Updating routing table: next hops for '%s' are %r", destination, self.routes[destination])
                ipdb.routes.add(dst=destination, multipath=multipath).commit()

    def add_route(self, destination, next_hop, metric):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a route with the same
        destination/next_hop already exists, it is erased by the new one. If a route with the same destination but with
        another next_hop exists, they coexists, with their own metric. If `destination` is None, it is the default
        route."""

        # Get real destination
        if destination is None:
            destination = "default"
        elif '/' not in destination:
            # Suppose it is a host route
            destination += "/32"

        # Update the routing table
        try:
            self.routes[destination][next_hop] = metric
        except KeyError:
            self.routes[destination] = {next_hop: metric}

        # Synchronize netlink
        self._update_route(destination)

    def filter_out(self, destination, max_metric: int=None):
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
            self._update_route(destination)

    def _flush_routes(self):
        self.logger.debug("Flush all routes")
        with pyroute2.IPDB() as ipdb:
            for key in ipdb.routes.keys():
                route = ipdb.routes[key]
                self.logger.debug("Drop a route towards %s" % route['dst'])
                route.remove().commit()


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

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")
        self.bdc_out_socket.close()
        self.bdc_in_socket.close()
        self.uni_socket.close()

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
            rr, _, _ = select.select([self.bdc_in_socket, self.uni_socket], [], [])
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
