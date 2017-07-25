import logging
import select
import socket
import struct

import click
import pyroute2

import lrp
from lrp.message import RREP, DIO


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
        self.routing_table = {}

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

        with pyroute2.IPDB() as ipdb:
            self.logger.debug("Flush all routes")
            for route in ipdb.routes:
                self.logger.debug("Drop a route towards %s" % route['dst'])
                route.remove().commit()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")
        self.bdc_out_socket.close()
        self.bdc_in_socket.close()
        self.uni_socket.close()

    def ensure_is_neighbor(self, address):
        """Check if neighbor is declared. If it is not, it is added as neighbor."""
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            if address not in ipdb.routes:
                self.logger.info("Adding %s as neighbor" % address)
                ipdb.routes.add(dst=address, oif=self.idx,
                                scope=pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK'],
                                proto=pyroute2.netlink.rtnl.rtprotos['RTPROT_STATIC']) \
                    .commit()

    def is_neighbor(self, address):
        """Check if neighbor is declared. Contrary to `LrpProcess.ensure_is_neighbor`, the neighbor is not added if it
        was not known."""
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            try:
                return ipdb.routes[address]['scope'] == pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK']
            except KeyError:
                # address is unknown, it is certainly not a neighbor
                return False

    def get_a_successor(self):
        try:
            with pyroute2.IPRoute() as ipr:
                return ipr.get_default_routes()[0].get_attr('RTA_GATEWAY')
        except IndexError:
            # No default route
            return None

    def get_a_nexthop(self, destination):
        try:
            with pyroute2.IPRoute() as ipr:
                return ipr.route('get', dst=destination)[0].get_attr('RTA_GATEWAY')
        except pyroute2.netlink.exceptions.NetlinkError:
            # No route towards destination
            return None

    def wait_event(self):
        self.broadcast_message(DIO(self.own_metric))
        while True:
            rr, _, _ = select.select([self.bdc_in_socket, self.uni_socket], [], [], None)
            data, (sender, _) = rr[0].recvfrom(16)
            if sender == self.own_ip:
                self.logger.debug("Skip a message from ourselves")
                continue
            msg = lrp.message.Message.parse(data)
            self.logger.info("Received %s from %s", msg, sender)
            self.ensure_is_neighbor(sender)

            if isinstance(msg, DIO):
                route_cost = msg.metric_value + 1
                if self.own_metric < route_cost:
                    self.logger.debug("Do not use DIO: route is too bad")
                    if self.own_metric + 2 < route_cost:
                        self.logger.info("Neighbor may be interested by our DIO")
                        self.broadcast_message(DIO(self.own_metric))
                else:
                    with pyroute2.IPDB() as ipdb:
                        try:
                            with ipdb.routes['default'] as default_route:
                                self.logger.debug("Drop current default route")
                                default_route.remove()
                        except KeyError:
                            # No default route, ok.
                            pass

                        self._successors[sender] = route_cost

                        if self.own_metric > route_cost:
                            self.logger.info("Update our metric to %d", route_cost)
                            self.own_metric = route_cost

                            self.logger.debug("Check if old successors are still usable")
                            for successor in list(self._successors.keys()):
                                if self._successors[successor] > self.own_metric:
                                    self.logger.info("Drop successor '%s': too high metric (was %d)", successor,
                                                     self._successors[successor])
                                    del self._successors[successor]

                            self.logger.debug("Inform neighbors that we have changed our metric")
                            self.broadcast_message(DIO(self.own_metric))

                        if len(self._successors) != 0:
                            multipath = [{'gateway': key, 'hops': value} for key, value in self._successors.items()]
                            ipdb.routes.add(dst="default", multipath=multipath).commit()

                        # TODO: we send RREP at each successor change. We should do that only sometimes.
                        self.logger.info("Refresh host route")
                        nexthop = self.get_a_successor()
                        if nexthop is not None:
                            self.send_msg(RREP(self.own_ip, "172.18.0.1", 0), destination=nexthop)
                        else:
                            self.logger.warning("Not sending RREP: no more successor")

            elif isinstance(msg, RREP):
                with pyroute2.IPDB() as ipdb:
                    route_cost = msg.hops + 1

                    if not self.is_neighbor(msg.source):
                        try:
                            with ipdb.routes[msg.source] as route:
                                self.logger.debug("Drop the current route towards %s" % msg.source)
                                route.remove()
                        except KeyError:
                            # No such route, ok.
                            pass

                        # Update own routing table
                        try:
                            self.routing_table[msg.source][sender] = route_cost
                        except KeyError:
                            self.routing_table[msg.source] = {sender: route_cost}

                        # Recreate the route
                        if len(self.routing_table[msg.source]) != 0:
                            multipath = [{'gateway': key, 'hops': value} for key, value in
                                         self.routing_table[msg.source].items()]
                            self.logger.info("Updating routing table: next hops for %s are %r", msg.source,
                                             self.routing_table[msg.source])
                            ipdb.routes.add(dst=msg.source + "/32", multipath=multipath).commit()

                    # Update RREP
                    msg.hops = route_cost

                    # Forward RREP
                    if msg.destination == self.own_ip:
                        self.logger.debug("RREP has reached its destination")
                    else:
                        nexthop = self.get_a_nexthop(msg.destination)
                        if nexthop is not None:
                            self.logger.info("Forward RREP farther")
                            self.send_msg(msg, destination=nexthop)
                        else:
                            self.logger.info("Drop RREP: no route towards %s" % msg.destination)
            else:
                self.logger.warning("Received unknown message type: %d" % msg.message_type)

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
