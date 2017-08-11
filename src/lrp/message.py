import abc
import enum

import lrp
from lrp.tools import Address


class MessageType(enum.IntEnum):
    RREQ = 0
    RREP = 1
    RREP_ACK = 2
    RERR = 3
    DIO = 4
    BRK = 6
    UPD = 7
    HELLO = 8

    def __str__(self):
        return "%s" % self._name_


class Message(metaclass=abc.ABCMeta):
    __slots__ = ("message_type",)
    _message_types = {}

    @classmethod
    def parse(cls, flow: bytearray):
        """Deserialize a message. @see dump.
        flow: the message content
        :return a instance of a subclass of Message
        """
        msg_type = flow[0]
        try:
            return cls._message_types[msg_type].parse(flow)
        except IndexError:
            raise Exception("%d: unknown message type" % msg_type)

    def dump(self) -> bytearray:
        """Serialize. @see parse."""
        return self.message_type.to_bytes(1, lrp.conf['endianess'])

    @classmethod
    def record_message_type(cls, the_class):
        Message._message_types[the_class.message_type] = the_class
        return the_class

    def __str__(self):
        return "%s <%s>" % (self.message_type, " ".join("%s=%s" % (attr_name, self.__getattribute__(attr_name))
                                                        for attr_name in self.__slots__))


@Message.record_message_type
class DIO(Message):
    __slots__ = ("metric_value", "sink")
    message_type = MessageType.DIO

    @classmethod
    def parse(cls, flow):
        metric_value = int.from_bytes(flow[1:3], lrp.conf['endianess'])
        sink = Address(flow[3:7])
        return cls(metric_value, sink)

    def __init__(self, metric_value: int, sink: Address):
        self.metric_value = metric_value
        self.sink = sink

    def dump(self):
        result = b""
        result += self.metric_value.to_bytes(2, lrp.conf['endianess'])
        result += self.sink.as_bytes
        return super(DIO, self).dump() + result


@Message.record_message_type
class RREP(Message):
    __slots__ = ("source", "destination", "hops")
    message_type = MessageType.RREP

    @classmethod
    def parse(cls, flow):
        source = Address(flow[1:5])
        destination = Address(flow[5:9])
        hops = int.from_bytes(flow[9:11], lrp.conf['endianess'])
        return cls(source, destination, hops)

    def __init__(self, source: Address, destination: Address, hops: int):
        self.source = source
        self.destination = destination
        self.hops = hops

    def dump(self):
        result = b""
        result += self.source.as_bytes
        result += self.destination.as_bytes
        result += self.hops.to_bytes(2, lrp.conf['endianess'])
        return super(RREP, self).dump() + result


@Message.record_message_type
class RERR(Message):
    __slots__ = ("error_source", "error_destination")
    message_type = MessageType.RERR

    @classmethod
    def parse(cls, flow):
        error_source = Address(flow[1:5])
        error_destination = Address(flow[5:9])
        return cls(error_source, error_destination)

    def __init__(self, error_source: Address, error_destination: Address):
        self.error_source = error_source
        self.error_destination = error_destination

    def dump(self):
        result = b""
        result += self.error_source.as_bytes
        result += self.error_destination.as_bytes
        return super().dump() + result


@Message.record_message_type
class RREQ(Message):
    __slots__ = ("searched_node", "source", "seqno")
    message_type = MessageType.RREQ

    @classmethod
    def parse(cls, flow):
        searched_node = Address(flow[1:5])
        source = Address(flow[5:9])
        seqno = int.from_bytes(flow[9:11], lrp.conf['endianess'])
        return cls(searched_node, source, seqno)

    def __init__(self, searched_node: Address, source: Address, seqno):
        self.searched_node = searched_node
        self.source = source
        self.seqno = seqno

    def dump(self):
        result = b""
        result += self.searched_node.as_bytes
        result += self.source.as_bytes
        result += self.seqno.to_bytes(2, lrp.conf['endianess'])
        return super().dump() + result
