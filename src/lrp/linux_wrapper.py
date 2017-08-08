#!/usr/bin/env python3
import netfilterqueue
import select
import socket
import struct

import click
import iptc
import pyroute2

import lrp
from lrp.daemon import LrpProcess
from lrp.message import Message


class LinuxLrpProcess(LrpProcess):
    """Linux toolbox to make LrpProcess works on native linux. It supposes that
    netlink and netfilter are available on the system."""

    non_routable_queue_nb = 7

    def __init__(self, interface, **remaining_kwargs):
        self.interface = interface
        super().__init__(**remaining_kwargs)
        self.non_routables_queue = netfilterqueue.NetfilterQueue()
        self.routes = {}
        self._hr_destinations = {}
        self._predecessors = {}

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
        self.output_multicast_socket.bind((self.own_ip, 0))
        self.output_multicast_socket.connect((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize input multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.input_multicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.input_multicast_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                                               struct.pack("=4s4s", multicast_address_as_bytes, iface_address_as_bytes))
        self.input_multicast_socket.bind((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize unicast socket ([%s]:%d)", iface_address, lrp.conf['service_port'])
        self.unicast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.unicast_socket.bind((self.own_ip, lrp.conf['service_port']))

        # Initialize netfilter
        self._netfilter_non_routable_table = iptc.Table(iptc.Table.FILTER)
        self._netfilter_non_routable_chain = iptc.Chain(self._netfilter_non_routable_table, "FORWARD")
        self.logger.debug("Flush firewall rules")
        self._netfilter_non_routable_chain.flush()

        self.logger.debug("Add firewall rule for non-routable packets")
        self._non_routable_rule = iptc.Rule()
        self._non_routable_rule.target = iptc.Target(self._non_routable_rule, "NFQUEUE")
        self._non_routable_rule.target.queue_num = str(self.non_routable_queue_nb)
        self._netfilter_non_routable_chain.append_rule(self._non_routable_rule)
        self._netfilter_non_routable_table.commit()

        # Initialize netfilter queue
        self.logger.debug("Bind netfilter non-routable packets to queue %d", self.non_routable_queue_nb)

        def queue_packet_handler(packet):
            payload = packet.get_payload()
            source = socket.inet_ntoa(payload[12:16])
            destination = socket.inet_ntoa(payload[16:20])
            sender = ":".join(["%02x" % b for b in packet.get_hw()[0:6]])
            self.handle_non_routable_packet(source, destination, sender)
            packet.drop()

        self.non_routables_queue.bind(self.non_routable_queue_nb, queue_packet_handler)
        self._non_routables_socket = socket.fromfd(self.non_routables_queue.get_fd(),
                                                   socket.AF_UNIX, socket.SOCK_STREAM)  # Used to 'select' on.

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

        # Clean netfilter
        # Drop netfilter rules for packets following a host route
        for rule in self._hr_destinations.values():
            self.logger.debug("Clean firewall rule towards %s", rule.dst)
            self._netfilter_non_routable_chain.delete_rule(rule)
        self._hr_destinations.clear()

        # Drop netfilter rules for packets coming from a predecessor
        for rule in self._predecessors.values():
            self.logger.debug("Clean firewall rule through %s", rule.matches[0].mac_source)
            self._netfilter_non_routable_chain.delete_rule(rule)
        self._predecessors.clear()

        self.logger.debug("Clean netlink rule for non-routable packets")
        self._netfilter_non_routable_chain.delete_rule(self._non_routable_rule)
        self._non_routable_rule = None

        self.logger.debug("Clean non-routable queue")
        self._non_routables_socket.close()
        self.non_routables_queue.unbind()

        # Clean netlink
        with pyroute2.IPDB() as ipdb:
            # Drop all routes inserted by LRP in the kernel routing table
            for destination in self.routes:
                self.logger.debug("Clean route towards %s", destination)
                ipdb.routes[destination].remove().commit()
            self.routes.clear()

    @property
    def own_ip(self) -> str:
        try:
            return self._own_ip
        except AttributeError:
            # _own_ip was never computed
            with pyroute2.IPRoute() as ip:
                try:
                    self._own_ip = ip.get_addr(index=self.interface_idx)[0].get_attr('IFA_ADDRESS')
                except IndexError:
                    raise Exception("%s: interface has no IP address" % self.interface)
            return self._own_ip

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
            rr, _, _ = select.select([self.input_multicast_socket, self.unicast_socket, self._non_routables_socket], [],
                                     [])
            if rr[0] is self._non_routables_socket:
                self.non_routables_queue.run(block=False)
            else:
                data, (sender, _) = rr[0].recvfrom(16)
                if sender == self.own_ip:
                    self.logger.debug("Skip a message from ourselves")  # Happen on broadcast messages
                    continue
                msg = Message.parse(data)
                self.handle_msg(msg, sender, is_broadcast=rr[0] is self.input_multicast_socket)

    def send_msg(self, msg: Message, destination=None):
        if destination is None:
            self.logger.info("Send %s (multicast)", msg)
            self.output_multicast_socket.send(msg.dump())
        else:
            self.logger.info("Send %s to %s", msg, destination)
            self.unicast_socket.sendto(msg.dump(), (destination, lrp.conf['service_port']))

    def ensure_is_neighbor(self, address):
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            if address not in ipdb.routes:
                self.logger.info("Adding %s as neighbor" % address)
                ipdb.routes.add(dst=address, oif=self.interface_idx,
                                scope=pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK'],
                                proto=pyroute2.netlink.rtnl.rtprotos['RTPROT_STATIC']) \
                    .commit()

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

    def get_mac_from_ip(self, ip_address):
        try:
            with pyroute2.IPRoute() as ipr:
                return ipr.neigh("dump", dst=ip_address)[0].get_attr('NDA_LLADDR').upper()
        except IndexError:
            # Unknown IP address
            return None

    def get_ip_from_mac(self, mac_address):
        try:
            with pyroute2.IPRoute() as ipr:
                return ipr.neigh("dump", lladdr=mac_address.lower())[0].get_attr('NDA_DST')
        except IndexError:
            # Unknown MAC address
            return None

    def add_route(self, destination, next_hop, metric):
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
            if destination != "default":
                self._netfilter_ensure_is_destination(destination)

        # Synchronize netlink and netfilter
        self._netlink_update_route(destination)
        if destination != "default":
            self._netfilter_ensure_is_predecessor(next_hop)

    def del_route(self, destination, next_hop):
        # Get real destination
        if destination is None or destination == "0.0.0.0/0":
            destination = "default"
        elif '/' not in destination:
            # Suppose it is a host route
            destination += "/32"

        # Update the routing table
        try:
            del self.routes[destination][next_hop]
        except KeyError:
            self.logger.warning("Attempting to delete route towards %s through %s, while it does not exists",
                                destination, next_hop)

        # Synchronize netlink
        self._netlink_update_route(destination)

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

    def _netfilter_ensure_is_predecessor(self, predecessor_ip):
        """Ensure this node is known as a predecessor by the firewall."""
        self._netfilter_non_routable_table.refresh()
        predecessor_mac = self.get_mac_from_ip(predecessor_ip)
        # Find the rule corresponding to this predecessor in netfilter
        for rule in self._netfilter_non_routable_chain.rules:
            try:
                if rule.matches[0].mac_source == predecessor_mac:
                    break
            except (IndexError, AttributeError):
                pass
        # Unable to find it. Add is as predecessor
        else:
            rule = iptc.Rule()
            match = iptc.Match(rule, "mac")
            match.mac_source = predecessor_mac
            rule.add_match(match)
            rule.target = iptc.Target(rule, "ACCEPT")
            self._netfilter_non_routable_chain.insert_rule(rule)
            self._predecessors[predecessor_ip] = rule
            self._netfilter_non_routable_table.commit()
            self.logger.info("%s is now known as predecessor", predecessor_ip)

    def _netfilter_ensure_is_destination(self, destination):
        """Ensure this node is known as a host route destination by the firewall."""
        self._netfilter_non_routable_table.refresh()
        for rule in self._netfilter_non_routable_chain.rules:
            if rule.dst == destination:
                # `destination` is already a host route destination
                break
        else:
            rule = iptc.Rule()
            rule.dst = destination
            rule.target = iptc.Target(rule, "ACCEPT")
            self._netfilter_non_routable_chain.insert_rule(rule)
            self._hr_destinations[destination] = rule
            self._netfilter_non_routable_table.commit()
            self.logger.info("%s is now known as host route destination", destination)

    def _netlink_update_route(self, destination):
        """Must be called whenever self.routes[destination] has changed. Keep netlink
        synchronized with this change."""

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
            try:
                if len(self.routes[destination]) != 0:
                    multipath = [{'gateway': key, 'hops': value} for key, value in self.routes[destination].items()]
                    self.logger.info("Updating routing table: next hops for '%s' are %r", destination,
                                     self.routes[destination])
                    ipdb.routes.add(dst=destination, multipath=multipath).commit()
            except KeyError:
                # No such route, don't need to insert it. Ok.
                pass


@click.command()
@click.argument("interface")
@click.argument("metric", default=2 ** 16 - 1)
@click.option("--sink/--no-sink")
def daemon(interface, metric, sink=False):
    with LinuxLrpProcess(interface, metric=metric, is_sink=sink) as lrp_process:
        lrp_process.wait_event()


if __name__ == '__main__':
    daemon()
