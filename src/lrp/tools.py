import socket

import logging
from typing import Dict, Tuple, List, Optional

import lrp


class Address:
    def __init__(self, address):
        if isinstance(address, str):
            self.as_bytes = socket.inet_aton(address)
        elif isinstance(address, bytes):
            if len(address) != 4:
                raise Exception("Unsupported address length for %r" % address)
            self.as_bytes = address
        else:
            raise TypeError("Unsupported address type: %s" % type(address))

    def __eq__(self, other):
        return isinstance(other, Address) and self.as_bytes == other.as_bytes

    def __hash__(self):
        return self.as_bytes.__hash__()

    def __str__(self):
        return socket.inet_ntoa(self.as_bytes)

    def as_subnet(self):
        return "%s/32" % socket.inet_ntoa(self.as_bytes)


# Create special instance
NULL_ADDRESS = Address(b"\x00\x00\x00\x00")
MULTICAST_ADDRESS = Address(lrp.conf['service_multicast_address'])


class Subnet(Address):
    def __init__(self, address, prefix: int = 32):
        if isinstance(address, Address):
            super().__init__(address.as_bytes)
        else:
            super().__init__(address)
        self.prefix = prefix

    def __contains__(self, item):
        if not isinstance(item, Address):
            raise TypeError("A %s cannot be in a %s" % (type(item).__name__, type(self).__name__))
        if self.as_bytes[0:(self.prefix // 8)] != item.as_bytes[0:(self.prefix // 8)]:
            return False
        return self.as_bytes[self.prefix // 8] >> self.prefix % 8 == item.as_bytes[self.prefix // 8] >> self.prefix % 8

    def __eq__(self, other):
        return isinstance(other, Subnet) and self.as_bytes == other.as_bytes and self.prefix == other.prefix

    def __hash__(self):
        return (self.as_bytes + bytes(self.prefix)).__hash__()

    def __str__(self):
        if self is DEFAULT_ROUTE:
            return "default"
        return "%s/%d" % (socket.inet_ntoa(self.as_bytes), self.prefix)


# Create special instance corresponding to default route
DEFAULT_ROUTE = Subnet(b"\x00\x00\x00\x00", prefix=0)


class Route:
    def __init__(self, destination: Subnet):
        self.destination = destination

        self.next_hops: Dict[Address, int] = {}
        self.on_link = False

    def add_nexthop(self, next_hop: Address, metric):
        """Add a next hop. If it already existed before, it is dropped. The other
        next hops are kept unchanged."""
        self.next_hops[next_hop] = metric

    def del_nexthop(self, next_hop: Address):
        """Delete a next hop. The others are kept unchanged."""
        del self.next_hops[next_hop]

    def get_a_nexthop(self) -> Optional[Address]:
        """Return the best next hop, according to the metric. If many are equal,
        return any of them."""
        try:
            return sorted(self.next_hops.items(), key=lambda item: item[1])[0][0]
        except IndexError:
            # No nexthop at all
            return None

    def is_nexthop(self, next_hop: Address) -> bool:
        """Return true if the provided next_hop is effectively a next_hop."""
        return next_hop in self.next_hops

    def filter_out_nexthops(self, max_metric: int = None) -> List[Tuple[Address, int]]:
        """Filter out some next hops, according to some constraints. Returns the list
        of dropped next hops"""
        dropped = []
        for nh in list(self.next_hops):
            # Filter according to max_metric
            if self.next_hops[nh] > max_metric:
                dropped.append((nh, self.next_hops[nh]))
                del self.next_hops[nh]
        return dropped


class RoutingTable:
    logger = logging.getLogger("RoutingTable")

    def __init__(self):
        self.routes: Dict[Address, Route] = {}

    def add_route(self, destination: Subnet, next_hop: Address, metric: int):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a
        route with the same destination/next_hop already exists, it is erased
        by the new one. If a route with the same destination but with another
        next_hop exists, they coexists, with their own metric. If `destination`
        is None, it is the default route."""
        try:
            self.routes[destination].add_nexthop(next_hop, metric)
        except KeyError:
            # Destination was unknown
            self.routes[destination] = Route(destination)
            self.routes[destination].add_nexthop(next_hop, metric)

    def del_route(self, destination: Subnet, next_hop: Address):
        """Delete the route to `destination`, through `next_hop`. If a route with the
        same destination but with another next_hop exists, the other one
        continues to exist. If `destination` is None, it is the default route."""
        try:
            self.routes[destination].del_nexthop(next_hop)
        except KeyError:
            self.logger.warning("When deleting next hop %s of route towards %s: no such next hop",
                                next_hop, destination)

    def filter_out_nexthops(self, destination: Subnet, **kwargs) -> List[Tuple[Address, int]]:
        """Filter out some next hops, according to some constraints. Returns the list
        of dropped next hops. @see Route.filter_out_nexthops"""
        try:
            route = self.routes[destination]
        except KeyError:
            # No route, no next hop to filter
            return []
        else:
            return route.filter_out_nexthops(**kwargs)

    def is_successor(self, nexthop: Address) -> bool:
        """Check if a node is known as a successor."""
        try:
            default_route = self.routes[DEFAULT_ROUTE]
        except KeyError:
            # No default route => no successor at all.
            return False
        else:
            return default_route.is_nexthop(nexthop)

    def get_a_nexthop(self, destination: Address) -> Optional[Address]:
        """Return the best next hop for this destination, according to the metric. If
        many are equal, return any of them."""
        try:
            route = self.routes[destination]
        except KeyError:
            # No route, no next hop
            return None
        else:
            return route.get_a_nexthop()

    def ensure_is_neighbor(self, neighbor: Address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""
        for destination, route in self.routes.items():
            if neighbor in destination and route.on_link:
                break
        else:
            # Not a neighbor. Add it as neighbor
            destination = Subnet(neighbor)
            self.routes[destination] = Route(destination)
            self.routes[destination].on_link = True

    def is_neighbor(self, neighbor: Address) -> bool:
        """Check if neighbor is declared. Contrary to `LrpProcess.ensure_is_neighbor`, the neighbor is not added if it
        was not known."""
        for destination, route in self.routes.items():
            if neighbor in destination and route.on_link:
                return True
        return False
