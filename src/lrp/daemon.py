import abc
import logging

from lrp.message import RREP, DIO, Message


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
            self.sink = None

    def __enter__(self):
        self.logger.debug("LRP process started")
        if self.is_sink:
            self.logger.debug("Started as sink")

        self.logger.debug("Emit a first DIO to signal our presence")
        self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")

    @property
    @abc.abstractmethod
    def own_ip(self) -> str:
        """The IP address of this node"""

    @abc.abstractmethod
    def send_msg(self, msg: Message, destination=None):
        """Send a LRP message to a node.

        msg: the Message to be sent
        destination: The IP address of the destination. If None, broadcast the packet.
        """

    @abc.abstractmethod
    def ensure_is_neighbor(self, address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""

    @abc.abstractmethod
    def is_successor(self, address):
        """Check if a node is known as a successor."""

    @abc.abstractmethod
    def get_nexthop(self, destination=None):
        """Get a next_hop towards a `destination`. If `destination` is None, get a
        successor. If there is no such next hop, return None"""

    @abc.abstractmethod
    def get_ip_from_mac(self, mac_address):
        """Return the layer 3 address, given a layer 2 address. Return None if such
        layer 2 address is unknown"""

    def handle_msg(self, msg, sender, is_broadcast: bool):
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

    def _handle_DIO(self, dio, sender, is_broadcast):
        # Compute real route cost
        route_cost = dio.metric_value + 1

        # Check if this sink is supported
        if dio.sink is not None and self.sink is not None and dio.sink != self.sink:
            self.logger.warning("Drop DIO: not the same sink (many sinks are not handled now)")

        elif dio.sink is None or self.own_metric < route_cost:
            self.logger.debug("Do not use DIO: route is too bad")
            if self.own_metric + 2 < route_cost:
                self.logger.info("Neighbor may be interested by our DIO")
                self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)

        else:
            self.logger.debug("Neighbor %s is an acceptable successor", sender)
            was_already_successor = self.is_successor(sender)

            # Add route
            self.add_route(None, sender, route_cost)

            # Update position in the DODAG
            if self.own_metric > route_cost:
                self.logger.info("Update our metric to %d", route_cost)
                self.own_metric = route_cost

                if self.sink != dio.sink:
                    assert self.sink is None, \
                        "Trying to change the sink we are attached to (%s -> %s)" % (self.sink, dio.sink)
                    self.logger.info("Update our sink to %s", dio.sink)
                    self.sink = dio.sink

                self.logger.debug("Check if old successors are still usable")
                self.filter_out(destination=None, max_metric=self.own_metric + 1)

                self.logger.debug("Inform neighbors that we have changed our metric")
                self.send_msg(DIO(self.own_metric, sink=self.sink), destination=None)

            if not was_already_successor:
                # This neighbor does not know us as predecessor. Send RREP
                self.logger.info("Create host route through %s" % sender)
                self.send_msg(RREP(self.own_ip, self.sink, 0), destination=sender)

    def _handle_RREP(self, rrep, sender, is_broadcast):
        assert not is_broadcast, "Broadcast RREP are unacceptable"

        # Real route cost: msg.hops is only the distance between the sender and the destination, without the link
        # between here and the sender
        route_cost = rrep.hops + 1

        self.add_route(rrep.source, sender, route_cost)

        # Update and forward RREP
        rrep.hops = route_cost
        if rrep.destination == self.own_ip:
            self.logger.debug("RREP has reached its destination")
        else:
            nexthop = self.get_nexthop(rrep.destination)
            if nexthop is not None:
                assert self.is_successor(nexthop), \
                    "Trying to send a RREP through %s, which is not a successor (forbidden!)" % nexthop
                self.logger.info("Forward RREP to %s", nexthop)
                self.send_msg(rrep, destination=nexthop)
            else:
                self.logger.error("Unable to forward %s: no route towards %s", rrep.message_type, rrep.destination)

    def handle_non_routable_packet(self, source, destination, sender):
        self.logger.warning("Drop a non-routable packet: %s --(%s)--> %s", source, sender, destination)

    @abc.abstractmethod
    def add_route(self, destination, next_hop, metric):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a
        route with the same destination/next_hop already exists, it is erased
        by the new one. If a route with the same destination but with another
        next_hop exists, they coexists, with their own metric. If `destination`
        is None, it is the default route."""

    @abc.abstractmethod
    def del_route(self, destination, next_hop):
        """Delete the route to `destination`, through `next_hop`. If a route with the
        same destination but with another next_hop exists, the other one
        continues to exist. If `destination` is None, it is the default route."""

    @abc.abstractmethod
    def filter_out(self, destination, max_metric: int = None):
        """Filter out some routes, according to some constraints."""
