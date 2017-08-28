import socket

import logging
from typing import Dict, Tuple, List, Optional, Set

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
        if isinstance(item, Subnet) and item.prefix < self.prefix:
            return False
        mask = ((2 ** self.prefix - 1) << (32 - self.prefix))
        return int.from_bytes(self.as_bytes, "big") & mask == \
               int.from_bytes(item.as_bytes, "big") & mask

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


class RoutingTable:
    logger = logging.getLogger("RoutingTable")

    def __init__(self):
        self.routes: Dict[Subnet, Dict[Address, int]] = {}
        self.neighbors: Set[Address] = set()

    def add_route(self, destination: Subnet, next_hop: Address, metric: int):
        """Add a route to `destination`, through `next_hop`, with cost `metric`. If a
        route with the same destination/next_hop already exists, it is erased
        by the new one. If a route with the same destination but with another
        next_hop exists, they coexists, with their own metric. If `destination`
        is None, it is the default route."""
        try:
            next_hops = self.routes[destination]
        except KeyError:
            # Destination was unknown
            next_hops = self.routes[destination] = {next_hop: metric}
        else:
            next_hops[next_hop] = metric
        self.logger.info("Update routing table: next hops for %s are {%s}",
                         destination, ", ".join(map(str, next_hops)))

    def del_route(self, destination: Subnet, next_hop: Address):
        """Delete the route to `destination`, through `next_hop`. If a route with the
        same destination but with another next_hop exists, the other one
        continues to exist. If `destination` is None, it is the default route."""
        try:
            next_hops = self.routes[destination]
        except KeyError:
            # Unknown destination, no such next_hop, ok.
            pass
        else:
            del next_hops[next_hop]

    def filter_out_nexthops(self, destination: Subnet, **kwargs) -> List[Tuple[Address, int]]:
        """Filter out some next hops, according to some constraints. Returns the list
        of dropped next hops. @see Route.filter_out_nexthops"""
        try:
            next_hops = self.routes[destination]
        except KeyError:
            # No route, no next hop to filter
            return []
        else:
            dropped = []
            for nh, metric in list(next_hops.items()):
                # Filter according to max_metric
                if max_metric is not None and metric > max_metric:
                    dropped.append((nh, metric))
                    del next_hops[nh]
            return dropped

    def is_successor(self, nexthop: Address) -> bool:
        """Check if a node is known as a successor."""
        try:
            default_next_hops = self.routes[DEFAULT_ROUTE]
        except KeyError:
            # No default route => no successor at all.
            return False
        else:
            return nexthop in default_next_hops

    def get_a_nexthop(self, destination: Address) -> Optional[Address]:
        """Return the best next hop for this destination, according to the metric. If
        many are equal, return any of them."""
        for route_dest, next_hops in self.routes.items():
            if destination in route_dest:
                return sorted(next_hops.items(), key=lambda item: item[1])[0][0]
        else:
            # No route matches this destination
            return None

    def ensure_is_neighbor(self, neighbor: Address):
        """Check if neighbor is declared. If it is not, add it as neighbor."""
        self.neighbors.add(neighbor)

    def is_neighbor(self, neighbor: Address) -> bool:
        """Check if neighbor is declared. Contrary to `LrpProcess.ensure_is_neighbor`,
        the neighbor is not added if it was not known."""
        return neighbor in self.neighbors
