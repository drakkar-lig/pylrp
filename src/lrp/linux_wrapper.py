#!/usr/bin/env python3
import errno
import logging
import netfilterqueue
import select
import socket
import struct
from typing import Optional, List, Tuple, Union

import click
import pyroute2
from pyroute2.netlink.rtnl import ifinfmsg, rt_scope

import lrp
from lrp.daemon import LrpProcess
from lrp.message import Message
from lrp.tools import Address, Subnet, RoutingTable


class LinuxLrpProcess(LrpProcess):
    """Linux toolbox to make LrpProcess works on native linux. It supposes that
    netlink and netfilter are available on the system."""

    non_routable_queue_nb = 7

    def __init__(self, interface, **remaining_kwargs):
        self.interface = interface
        super().__init__(**remaining_kwargs)
        self.routing_table = NetlinkRoutingTable(interface_idx=self.interface_idx)

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

        # Initialize LRP itself
        return super().__enter__()

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Clean LRP itself
        super().__exit__(exc_type, exc_val, exc_tb)

        # Close sockets
        self.logger.debug("Close service sockets")
        self.output_multicast_socket.close()
        self.input_multicast_socket.close()
        self.unicast_socket.close()

        # Clean the routing table
        self.routing_table.clean()

    @property
    def own_ip(self) -> Address:
        try:
            return self._own_ip
        except AttributeError:
            # _own_ip was never computed
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

    @property
    def interface_idx(self) -> int:
        try:
            return self._idx
        except AttributeError:
            # _idx was never computed
            with pyroute2.IPRoute() as ip:
                try:
                    self._idx = ip.link_lookup(ifname=self.interface)[0]
                except IndexError:
                    raise Exception("%s: unknown interface" % self.interface)
            return self._idx

    def wait_event(self):
        while True:
            # Handle timers
            next_time_event = self.scheduler.run(blocking=False)
            # Handle socket input, but stop when next time event occurs
            rr, _, _ = select.select([self.input_multicast_socket, self.unicast_socket],
                                     [], [], next_time_event)
            try:
                # Handle packet from socket
                readable_socket = rr[0]
                data, (sender, _) = readable_socket.recvfrom(16)
                sender = Address(sender)
                if sender == self.own_ip:
                    self.logger.debug("Skip a message from ourselves")  # Happen on broadcast messages
                else:
                    msg = Message.parse(data)
                    self.handle_msg(msg, sender, is_broadcast=(readable_socket is self.input_multicast_socket))
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

    def get_mac_from_ip(self, ip_address: Address):
        """Return the layer 2 address, given a layer 3 address. Return None if such
        address is unknown"""
        try:
            with pyroute2.IPRoute() as ipr:
                return ipr.neigh("dump", dst=str(ip_address))[0].get_attr('NDA_LLADDR').upper()
        except IndexError:
            # Unknown IP address
            return None

    def get_ip_from_mac(self, mac_address) -> Optional[Address]:
        """Return the layer 3 address, given a layer 2 address. Return None if such
        layer 2 address is unknown"""
        try:
            with pyroute2.IPRoute() as ipr:
                return Address(ipr.neigh("dump", lladdr=mac_address.lower())[0].get_attr('NDA_DST'))
        except IndexError:
            # Unknown MAC address
            return None


class NetlinkRoutingTable(RoutingTable):
    def __init__(self, interface_idx: int):
        super().__init__()
        self.ipr = pyroute2.IPRoute()
        self.ipdb = pyroute2.IPDB()
        self.idx = interface_idx

    def add_route(self, destination: Subnet, next_hop: Address, metric: int):
        super().add_route(destination, next_hop, metric)
        self._netlink_update_route(destination)

    def del_route(self, destination: Subnet, next_hop: Address):
        super().del_route(destination, next_hop)
        self._netlink_update_route(destination)

    def filter_out_nexthops(self, destination: Subnet, max_metric: int = None) -> List[Tuple[Address, int]]:
        return_val = super().filter_out_nexthops(destination, max_metric)
        # Ensure netlink is up-to-date
        if len(return_val) > 0:
            self._netlink_update_route(destination)
        return return_val

    def ensure_is_neighbor(self, neighbor: Address):
        was_already_neighbor = neighbor in self.neighbors
        super().ensure_is_neighbor(neighbor)
        if not was_already_neighbor:
            self._netlink_update_route(Subnet(neighbor))

    def _netlink_update_route(self, destination: Union[Subnet, Address]):
        """Must be called whenever self.routes[destination] has changed, even
        if this entry has been dropped. Keep netlink synchronized with this
        change."""

        if (isinstance(destination, Address) and destination in self.neighbors) or \
                (destination.prefix == 32 and Address(destination) in self.neighbors):
            # Recorded as neighbor in local table
            self.logger.info("Update netlink routing table for neighbor %s", destination)
            self.ipr.route("replace", dst=str(destination), oif=self.idx,
                           scope=rt_scope['link'], proto=lrp.conf['netlink']['proto_number'])
        else:
            try:
                # Get the route in the routing table structure
                daemon_next_hops = self.routes[destination]
            except KeyError:
                # Route has been dropped. Just drop it, whatever is its state in netlink
                try:
                    self.ipr.route("delete", dst=str(destination), scope=rt_scope['nowhere'])
                    self.logger.info("Deleted route towards %s", destination)
                except pyroute2.netlink.exceptions.NetlinkError as e:
                    if e.code == errno.ESRCH:  # No such process => "no such route" in netlink's logic.
                        # Route did not exist, ok.
                        pass
                    else:
                        # Unknown exception
                        raise
            else:
                # Build the multipath host route
                self.logger.info("Updating netlink routing table for destination %s", destination)
                multipath = [{'gateway': str(nh), 'hops': metric} for nh, metric in daemon_next_hops.items()]
                self.ipr.route("replace", dst=str(destination), multipath=multipath)

    def clean(self):
        """Drop all routes inserted by this LRP process"""
        old_destinations = set(self.routes.keys())
        old_destinations.update(map(Subnet, self.neighbors))
        self.routes.clear()
        self.neighbors.clear()
        for destination in old_destinations:
            self._netlink_update_route(destination)


@click.command()
@click.option("--interface", default=None, metavar="<iface>",
              help="The interface LRP should use. Default: auto-detect.")
@click.option("--metric", default=2 ** 16 - 1, metavar="<metric>",
              help="The initial metric of this node. Should be set for the sink. Default: infinite.")
@click.option("--sink/--no-sink", default=False, help="Is this node a sink? Default: no.")
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
