import socket

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
            raise Exception("Unsupported address type: %s" % type(address))

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
