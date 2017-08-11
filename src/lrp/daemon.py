import abc
import logging
import sched

import lrp
from lrp.message import RREP, DIO, Message, RERR, RREQ
from lrp.tools import Address, Subnet, NULL_ADDRESS, DEFAULT_ROUTE


class LrpProcess(metaclass=abc.ABCMeta):
    logger = logging.getLogger("LRP")

    def __init__(self, metric: int = 2 ** 16 - 1, is_sink: bool = False):
        """Constructor.

        metric: The initial metric of the node. Should be set to a realistic value if is_sink is True.
        is_sink: Does this node is a LRP sink?"""
        self.is_sink = is_sink
        self.own_metric = metric

        if self.is_sink:
            self.sink = self.own_ip
        else:
            self.sink = NULL_ADDRESS

        self._tracked_rreq = {}
        self._own_current_seqno = 0
        self.scheduler = sched.scheduler()

    def __enter__(self):
        self.logger.debug("LRP process started")
        if self.is_sink:
            self.logger.debug("Started as sink")
            self.logger.debug("Emit a first DIO to signal our presence")
            self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)
        else:
            self.logger.debug("Started as standard node")
            self.disconnected()

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")

    @property
    @abc.abstractmethod
    def own_ip(self) -> Address:
        """The IP address of this node"""

    @abc.abstractmethod
    def send_msg(self, msg: Message, destination: Address = None):
        """Send a LRP message to a node.

        msg: the Message to be sent
        destination: The IP address of the destination. If None, broadcast the packet.
        """

    @abc.abstractmethod
    def ensure_is_neighbor(self, address: Address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""

    @abc.abstractmethod
    def is_successor(self, address: Address) -> bool:
        """Check if a node is known as a successor."""

    @abc.abstractmethod
    def get_nexthop(self, destination: Address = None) -> Address:
        """Get a next_hop towards a `destination`. If `destination` is None, get a
        successor. If there is no such next hop, return None"""

    @abc.abstractmethod
    def get_ip_from_mac(self, mac_address) -> Address:
        """Return the layer 3 address, given a layer 2 address. Return None if such
        layer 2 address is unknown"""

    def _new_rreq_seqno(self) -> int:
        self._own_current_seqno += 1
        if self._own_current_seqno >= 2 ** 16:
            self._own_current_seqno = 0
        return self._own_current_seqno

    def handle_msg(self, msg: Message, sender: Address, is_broadcast: bool):
        """Handle a LRP message.

        msg: the parsed message
        sender: the neighbor which has sent the msg
        is_broadcast: is it a broadcast message, or am I the destination?
        """
        try:
            handler = self.__getattribute__("_handle_" + str(msg.message_type))
        except AttributeError:
            self.logger.warning("Skip unknown message with type %d from %s to %s",
                                msg.message_type, sender, "broadcast" if is_broadcast else "myself")
        else:
            self.logger.info("Received message %s from %s to %s",
                             msg, sender, "broadcast" if is_broadcast else "myself")
            self.ensure_is_neighbor(sender)
            handler(msg, sender, is_broadcast)

    def _handle_DIO(self, dio: DIO, sender: Address, is_broadcast: bool):
        # Compute real route cost
        route_cost = dio.metric_value + 1

        # Check if this sink is supported
        if dio.sink != NULL_ADDRESS and self.sink != NULL_ADDRESS and dio.sink != self.sink:
            self.logger.warning("Drop DIO: not the same sink (many sinks are not handled now)")

        elif dio.sink == NULL_ADDRESS or self.own_metric < route_cost:
            self.logger.debug("Do not use DIO: route is too bad")
            if self.own_metric + 2 < route_cost:
                self.logger.info("Neighbor may be interested by our DIO")
                self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)

        else:
            self.logger.debug("Neighbor %s is an acceptable successor", sender)
            was_already_successor = self.is_successor(sender)

            # Add route
            self.add_route(DEFAULT_ROUTE, sender, route_cost)

            # Update position in the DODAG
            if self.own_metric > route_cost:
                self.logger.info("Update our metric to %d", route_cost)
                self.own_metric = route_cost

                if self.sink != dio.sink:
                    assert self.sink == NULL_ADDRESS, \
                        "Trying to change the sink we are attached to (%s -> %s)" % (self.sink, dio.sink)
                    self.logger.info("Update our sink to %s", dio.sink)
                    self.sink = dio.sink

                self.logger.debug("Check if old successors are still usable")
                self.filter_out(DEFAULT_ROUTE, max_metric=self.own_metric + 1)

                self.logger.debug("Inform neighbors that we have changed our metric")
                self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)

            if not was_already_successor:
                # This neighbor does not know us as predecessor. Send RREP
                self.logger.info("Create host route through %s" % sender)
                self.send_msg(RREP(self.own_ip, self.sink, 0), destination=sender)

    def _handle_RREP(self, rrep: RREP, sender: Address, is_broadcast: bool):
        assert not is_broadcast, "Broadcast RREP are unacceptable"

        # Real route cost: msg.hops is only the distance between the sender and the destination, without the link
        # between here and the sender
        route_cost = rrep.hops + 1

        self.add_route(Subnet(rrep.source), sender, route_cost)

        # Update and forward RREP
        rrep.hops = route_cost
        if rrep.destination == self.own_ip:
            self.logger.debug("RREP has reached its destination")
        elif self.is_sink:
            self.logger.warning("Do not forward a RREP through the sink")
        else:
            nexthop = self.get_nexthop(rrep.destination)
            if nexthop is not None:
                assert self.is_successor(nexthop), \
                    "Trying to send a RREP through %s, which is not a successor (forbidden!)" % nexthop
                self.logger.info("Forward RREP to %s", nexthop)
                self.send_msg(rrep, destination=nexthop)
            else:
                self.logger.error("Unable to forward %s: no route towards %s", rrep.message_type, rrep.destination)

    def _handle_RERR(self, rerr: RERR, sender: Address, is_broadcast: bool):
        if self.is_successor(sender):
            self.logger.info("Inform %s that we are its predecessor", sender)
            self.send_msg(RREP(source=self.own_ip, destination=self.sink, hops=0), destination=sender)
        else:
            # Remove host route towards the unreachable destination
            self.del_route(Subnet(rerr.error_destination), sender)

            if self.get_nexthop(rerr.error_destination) is not None:
                self.logger.info("Drop RERR: we still have a route towards %s", rerr.error_destination)
            else:
                # No more next hop towards rerr.error_destination. Forward RERR.
                next_hop = self.get_nexthop(rerr.error_source)
                if next_hop is None:
                    self.logger.warning("Unable to forward RERR: no route towards %s", rerr.error_source)
                else:
                    self.logger.info("Forward RERR")
                    self.send_msg(rerr, destination=next_hop)

    def _handle_RREQ(self, rreq: RREQ, sender: Address, is_broadcast: bool):
        # Throw out our messages
        if rreq.source == self.own_ip:
            self.logger.debug("Skip RREQ: it is mine")
        else:
            # Track RREQ seqnos
            try:
                old_seqno = self._tracked_rreq[rreq.source]
            except KeyError:
                # We do not have seqno for rreq.source. Accept this one.
                old_seqno = -1  # Does not really exist, but is below all seqnos
            if old_seqno >= rreq.seqno:
                self.logger.debug("Skip RREQ: already received")
            else:
                self._tracked_rreq[rreq.source] = rreq.seqno

                # Handle the message
                if rreq.searched_node == self.own_ip:
                    self.logger.info("We are the searched node. Answer with a RREP")
                    successor = self.get_nexthop(None)
                    if successor is None:
                        self.logger.error("Cannot send RREP: no more successor")
                    else:
                        self.send_msg(RREP(source=self.own_ip, destination=rreq.source, hops=0), destination=successor)
                else:
                    self.logger.info("Forward RREQ")
                    self.send_msg(rreq, destination=None)

    def handle_non_routable_packet(self, source: Address, destination: Address, sender_mac):
        """Handle non-routable packet: all packets that does not either come from a
        predecessor or follow a host route."""
        assert not self.is_sink, "The sink should be able to route any packet"
        self.logger.warning("Drop a non-routable packet: %s --(%s)--> %s", source, sender_mac, destination)
        sender_ip = self.get_ip_from_mac(sender_mac)
        if sender_ip is not None:
            self.send_msg(RERR(error_source=source, error_destination=destination), destination=sender_ip)
        else:
            self.logger.warning("Unable to warn about unreachable destination: unknown previous hop %s", sender_mac)

    def handle_unknown_host(self, destination: Address):
        """Handle the situation when the sink do not have a host route towards a node
        into the network."""
        assert self.is_sink, "Non-sink nodes does not handle unknown hosts, they use their default route instead"
        self.logger.info("Unknown host %s. Flooding a RREQ to find it", destination)
        self.send_msg(RREQ(searched_node=destination, source=self.own_ip, seqno=self._new_rreq_seqno()),
                      destination=None)

    @abc.abstractmethod
    def add_route(self, destination: Subnet, next_hop: Address, metric: int):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a
        route with the same destination/next_hop already exists, it is erased
        by the new one. If a route with the same destination but with another
        next_hop exists, they coexists, with their own metric. If `destination`
        is None, it is the default route."""

    @abc.abstractmethod
    def del_route(self, destination: Subnet, next_hop: Address):
        """Delete the route to `destination`, through `next_hop`. If a route with the
        same destination but with another next_hop exists, the other one
        continues to exist. If `destination` is None, it is the default route."""

    @abc.abstractmethod
    def filter_out(self, destination: Subnet, max_metric: int = None):
        """Filter out some routes, according to some constraints."""

    def disconnected(self):
        """Should be called whenever the node is detected as disconnected. Handle disconnection by sending regularly
        DIOs."""
        assert not self.is_sink, "Sink cannot be disconnected!"

        # Check if we already knows that we are disconnected
        for event in self.scheduler.queue:
            if event.action == self.disconnected:
                self.logger.debug("Disconnection already handled")
                break
        else:

            # Check if we are still disconnected
            successor = self.get_nexthop(None)
            if successor is not None:
                self.logger.info("Node is reconnected")
            else:

                # Handle disconnection
                self.logger.debug("Trying to connect the DODAG…")
                self.send_msg(DIO(metric_value=self.own_metric, sink=self.sink), destination=None)
                # Re-schedule next DIO emission
                self.scheduler.enter(lrp.conf['dio_reconnect_interval'], 0, action=self.disconnected)
