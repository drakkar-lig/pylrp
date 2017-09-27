#!/usr/bin/env python3
import errno
import logging
import netfilterqueue
import select
import socket
import struct
from typing import Optional, List, Tuple, Dict

import click
import iptc
import pyroute2
from pyroute2.ipdb.main import IPDB
from pyroute2.netlink.rtnl import ifinfmsg, rt_scope

import lrp
from lrp.daemon import LrpProcess
from lrp.message import Message
from lrp.tools import Address, Subnet, RoutingTable, DEFAULT_ROUTE


class LinuxLrpProcess(LrpProcess):
    """Linux toolbox to make LrpProcess works on native linux. It supposes that
    netlink and netfilter are available on the system."""

    def __init__(self, interface, **remaining_kwargs):
        self._own_ip = None
        self.interface = interface
        # Compute the interface id, based on its name
        with pyroute2.IPRoute() as ipr:
            try:
                self.interface_idx = ipr.link_lookup(ifname=self.interface)[0]
            except IndexError:
                raise Exception("%s: unknown interface" % self.interface)

        super().__init__(**remaining_kwargs)
        self.routing_table = NetlinkRoutingTable(self)
        self.non_routables_queue = netfilterqueue.NetfilterQueue()

    def __enter__(self):
        # Initialize sockets
        with pyroute2.IPRoute() as ip:
            iface_address = ip.get_addr(index=self.interface_idx)[0].get_attr('IFA_ADDRESS')
        self.logger.debug("Guess %s's address is '%s'", self.interface, iface_address)
        iface_address_as_bytes = socket.inet_aton(iface_address)
        multicast_address_as_bytes = socket.inet_aton(lrp.conf['service_multicast_address'])

        self.logger.debug("Initialize output multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.output_multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.output_multicast_socket.bind((str(self.own_ip), 0))
        self.output_multicast_socket.connect((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize input multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.input_multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.input_multicast_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                                               struct.pack("=4s4s", multicast_address_as_bytes, iface_address_as_bytes))
        self.input_multicast_socket.bind((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize unicast socket ([%s]:%d)", iface_address, lrp.conf['service_port'])
        self.unicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.unicast_socket.bind((str(self.own_ip), lrp.conf['service_port']))

        # Initialize the routing table
        self.routing_table.__enter__()

        # Initialize netfilter queue
        def queue_packet_handler(packet):
            """Handle a non-routable and activate corresponding LRP mechanisms"""
            payload = packet.get_payload()
            destination = socket.inet_ntoa(payload[16:20])
            if self.is_sink:
                self.handle_unknown_host(destination)
            else:
                source = socket.inet_ntoa(payload[12:16])
                sender = ":".join(["%02x" % b for b in packet.get_hw()[0:6]])
                self.handle_non_routable_packet(
                    source=Address(source), destination=Address(destination),
                    sender=Address(self.routing_table.get_ip_from_mac(sender)))
            packet.drop()

        self.non_routables_queue.bind(lrp.conf['netlink']['netfilter_queue_nb'], queue_packet_handler)
        # self.non_routables_queue.fileno = lambda: self.non_routables_queue.get_fd()

        # Initialize LRP itself
        return super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean LRP itself
        super().__exit__(exc_type, exc_val, exc_tb)

        # Clean the routing table
        self.routing_table.__exit__(exc_type, exc_val, exc_tb)

        # Close sockets
        self.logger.debug("Close service sockets")
        self.output_multicast_socket.close()
        self.input_multicast_socket.close()
        self.unicast_socket.close()

        # Close netfilter-queue
        self.non_routables_queue.unbind()

    @property
    def own_ip(self) -> Address:
        if self._own_ip is None:
            with pyroute2.IPRoute() as ip:
                try:
                    self._own_ip = Address(ip.get_addr(index=self.interface_idx)[0].get_attr('IFA_ADDRESS'))
                except IndexError:
                    raise Exception("%s: interface has no IP address" % self.interface)
        return self._own_ip

    @property
    def network_prefix(self) -> Subnet:
        # TODO: we do not manage any network prefix currently. This below
        # should work in the current configuration, but is not really
        # portable. Should be improved.
        prefix = Subnet(self.own_ip.as_bytes[0:2] + b"\x00\x00", prefix=16)
        return prefix

    def wait_event(self):
        queue_fd = self.non_routables_queue.get_fd()
        while True:
            # Handle timers
            next_time_event = self.scheduler.run(blocking=False)
            # Handle socket input, but stop when next time event occurs
            rr, _, _ = select.select([self.input_multicast_socket, self.unicast_socket, queue_fd],
                                     [], [], next_time_event)
            try:
                # Handle packet from socket or queue
                readable = rr[0]
                if readable == queue_fd:
                    self.non_routables_queue.run(block=False)
                else:
                    data, (sender, _) = readable.recvfrom(16)
                    sender = Address(sender)
                    if sender == self.own_ip:
                        self.logger.debug("Skip a message from ourselves")  # Happen on broadcast messages
                    else:
                        msg = Message.parse(data)
                        self.handle_msg(msg, sender, is_broadcast=(readable is self.input_multicast_socket))
            except IndexError:
                # No available readable socket. Select timed out. We have no new packet, but a timed event needs to
                # be activated. Loop.
                pass

    def send_msg(self, msg: Message, destination: Address = None):
        if destination is None:
            self.logger.info("Send %s (multicast)", msg)
            self.output_multicast_socket.send(msg.dump())
        else:
            self.logger.info("Send %s to %s", msg, destination)
            self.unicast_socket.sendto(msg.dump(), (str(destination), lrp.conf['service_port']))


class NetlinkRoutingTable(RoutingTable):
    def __init__(self, lrp_process: LinuxLrpProcess):
        super().__init__()
        self.ipdb = IPDB()
        self.lrp_process = lrp_process

    def __enter__(self):
        # Initialize netfilter
        self._non_routables_table = iptc.Table(iptc.Table.FILTER)
        self._non_routables_table.autocommit = False
        self._non_routables_chain = iptc.Chain(self._non_routables_table, "FORWARD")

        self.logger.debug("Redirect non-routables towards netfilter-queue %d",
                          lrp.conf['netlink']['netfilter_queue_nb'])
        self._non_routables_default_rule = iptc.Rule()
        if self.lrp_process.is_sink:
            # We are the sink: we expect to have a default route that does not
            # depend on the LRP network. Allow to use this route, except for
            # packets destined to the LRP network itself.
            self._non_routables_default_rule.dst = str(self.lrp_process.network_prefix)
        self._non_routables_default_rule.target = iptc.Target(self._non_routables_default_rule, "NFQUEUE")
        self._non_routables_default_rule.target.queue_num = str(lrp.conf['netlink']['netfilter_queue_nb'])
        self._non_routables_chain.append_rule(self._non_routables_default_rule)
        self._non_routables_table.commit()

    def __exit__(self, exc_type, exc_val, exc_tb):
        old_neighbors = set(self.neighbors)
        self.neighbors.clear()
        old_destinations = set(self.routes.keys())
        self.routes.clear()

        for neighbor in old_neighbors:
            self._nl_sync(Subnet(neighbor))
            self._nl_disallow_predecessor(neighbor)

        for destination in old_destinations - old_neighbors:
            self._nl_sync(destination)

        try:
            self._non_routables_table.refresh()
            self._non_routables_chain.delete_rule(self._non_routables_default_rule)
            self._non_routables_table.commit()
        except iptc.ip4tc.IPTCError:
            # Route does not exist, ok.
            pass

        self.ipdb.release()

    def get_mac_from_ip(self, ip_address: Address):
        """Return the layer 2 address, given a layer 3 address. Return None if such
        address is unknown"""
        table = self.ipdb.neighbours[self.lrp_process.interface_idx]
        try:
            return table[str(ip_address)]['lladdr'].upper()
        except KeyError:
            # Unknown IP address
            return None

    def get_ip_from_mac(self, mac_address) -> Optional[Address]:
        """Return the layer 3 address, given a layer 2 address. Return None if such
        layer 2 address is unknown"""
        table = self.ipdb.neighbours[self.lrp_process.interface_idx].raw.items()
        try:
            return [ip for ip, data in table if data['lladdr'] == mac_address.lower()][0]
        except IndexError:
            # Unknown MAC address
            return None

    def add_route(self, destination: Subnet, next_hop: Address, metric: int):
        super().add_route(destination, next_hop, metric)
        self._nl_sync(destination)
        if destination != DEFAULT_ROUTE:
            self._nl_allow_predecessor(next_hop)

    def del_route(self, destination: Subnet, next_hop: Address):
        super().del_route(destination, next_hop)
        self._nl_sync(destination)
        if not self.is_predecessor(next_hop):
            self._nl_disallow_predecessor(next_hop)

    def filter_out_nexthops(self, destination: Subnet, max_metric: int = None) -> List[Tuple[Address, int]]:
        dropped_nhs = super().filter_out_nexthops(destination, max_metric)
        for nh, _ in dropped_nhs:
            if not self.is_predecessor(nh):
                self._nl_disallow_predecessor(nh)
        return dropped_nhs

    def ensure_is_neighbor(self, neighbor: Address):
        was_already_neighbor = neighbor in self.neighbors
        super().ensure_is_neighbor(neighbor)
        if not was_already_neighbor:
            self._nl_sync(Subnet(neighbor))

    def _nl_sync(self, destination: Subnet):
        """Must be called whenever self.routes[destination] has changed, even
        if this entry has been dropped. Keep netlink synchronized with this
        change. If next_hop is given, """

        if destination.prefix == 32 and Address(destination) in self.neighbors:
            # Recorded as neighbor in local table
            self._nl_add_neighbor_route(destination)
            self._nl_allow_destination(destination)
        else:
            try:
                daemon_next_hops = self.routes[destination]
            except KeyError:
                # Route has been dropped. Just drop it, whatever is its state in netlink
                self._nl_drop_route(destination)
                self._nl_disallow_destination(destination)

            else:
                # Build the multipath host route
                self._nl_add_route(destination, daemon_next_hops)
                if destination != DEFAULT_ROUTE:
                    self._nl_allow_destination(destination)

    def _nl_add_neighbor_route(self, destination: Address):
        """Ensure netlink has a route towards the neighbor `destination`"""
        try:
            route = self.ipdb.routes[destination.as_subnet()]
        except KeyError:
            # Route does not exists. Will create it
            pass
        else:
            # Route is found. Ensure it is a neighbor route
            if route['scope'] == rt_scope['link']:
                # All is correct, nothing to do
                return

        self.logger.info("Create netlink route towards neighbor %s", destination)
        self.ipdb.routes.add({
            'dst': destination.as_subnet(),
            'oif': self.lrp_process.interface_idx,
            'scope': rt_scope['link'],
            'proto': lrp.conf['netlink']['proto_number']}).commit()

    def _nl_add_route(self, destination: Subnet, next_hops: Dict[Address, int]):
        self.logger.info("Update netlink route towards %s", destination)

        # Drop previous route
        try:
            self.ipdb.routes[str(destination)].remove().commit()
        except KeyError:
            # No route, ok.
            pass

        self.ipdb.routes.add({
            'dst': str(destination),
            'multipath': [{'gateway': str(nh), 'hops': metric} for nh, metric in next_hops.items()],
            'proto': lrp.conf['netlink']['proto_number']}).commit()

    def _nl_drop_route(self, destination):
        try:
            self.logger.info("Delete netlink route towards %s", destination)
            self.ipdb.routes[str(destination)].remove().commit()
        except KeyError:
            # No such route, ok
            pass

    def _nl_allow_predecessor(self, predecessor: Address):
        self._non_routables_table.refresh()
        predecessor_mac = self.get_mac_from_ip(predecessor)
        # Look for the rule allowing the predecessor
        for rule in self._non_routables_chain.rules:
            try:
                if rule.matches[0].mac_source == predecessor_mac:
                    # Found
                    break
            except IndexError:
                # Not this rule
                pass
        else:
            # Predecessor was not known. Add rule.
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = predecessor_mac
            rule.add_match(match)
            comment = iptc.Match(rule, "comment")
            comment.comment = "allow from predecessor %s" % predecessor
            rule.add_match(comment)
            rule.target = iptc.Target(rule, "ACCEPT")
            self._non_routables_chain.insert_rule(rule)
            self._non_routables_table.commit()
            self.logger.info("Traffic from %s is allowed", predecessor)

    def _nl_disallow_predecessor(self, predecessor: Address):
        self._non_routables_table.refresh()
        predecessor_mac = self.get_mac_from_ip(predecessor)
        # Look for the rule allowing the predecessor
        for rule in self._non_routables_chain.rules:
            try:
                if rule.matches[0].mac_source == predecessor_mac:
                    # Found. Delete this rule
                    self._non_routables_chain.delete_rule(rule)
                    self._non_routables_table.commit()
                    self.logger.info("Traffic from %s is no more allowed", predecessor)
            except IndexError:
                # Not this rule
                pass

    def _nl_allow_destination(self, destination: Subnet):
        self._non_routables_table.refresh()
        if not any(Subnet(rule.dst) == destination for rule in self._non_routables_chain.rules):
            # Destination was not known. Add rule.
            rule = iptc.Rule()
            rule.dst = str(destination)
            comment = iptc.Match(rule, "comment")
            comment.comment = "allow towards destination %s" % destination
            rule.add_match(comment)
            rule.target = iptc.Target(rule, "ACCEPT")
            self._non_routables_chain.insert_rule(rule)
            self._non_routables_table.commit()
            self.logger.info("Traffic towards %s is allowed", destination)

    def _nl_disallow_destination(self, destination: Subnet):
        self._non_routables_table.refresh()
        try:
            rule = [r for r in self._non_routables_chain.rules if Subnet(r.dst) == destination][0]
        except IndexError:
            # Destination is not known by netfilter, ok.
            pass
        else:
            self._non_routables_chain.delete_rule(rule)
            self._non_routables_table.commit()
            self.logger.info("Traffic towards %s is no more allowed", destination)


@click.command()
@click.option("--interface", default=None, metavar="<iface>",
              help="The interface LRP should use. Default: auto-detect.")
@click.option("--metric", default=2 ** 16 - 1, metavar="<metric>",
              help="The initial metric of this node. Should be set for the sink. Default: infinite.")
@click.option("--sink/--no-sink", default=False, help="Is this node a sink?", show_default=True)
def daemon(interface=None, metric=2 ** 16 - 1, sink=False):
    """Launch the LRP daemon."""
    if interface is None:
        # Guess interface
        with pyroute2.IPRoute() as ipr:
            all_interfaces = ipr.get_links()
        all_interfaces = [iface.get_attr("IFLA_IFNAME") for iface in all_interfaces
                          if not iface['flags'] & ifinfmsg.IFF_LOOPBACK]  # Filter out loopback
        if len(all_interfaces) > 1:
            raise Exception("Unable to auto-detect the interface to use. Please provide --interface argument.")
        elif len(all_interfaces) == 0:
            raise Exception("Unable to find a usable interface.")
        interface = all_interfaces[0]
        logging.getLogger("LRP").info("Use auto-detected interface %s", interface)

    with LinuxLrpProcess(interface, metric=metric, is_sink=sink) as lrp_process:
        lrp_process.wait_event()


if __name__ == '__main__':
    daemon()
