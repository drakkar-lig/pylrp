import abc
import enum
import socket

import lrp


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
    _message_types = {}
    message_type = None  # Should be filled by subclasses

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


@Message.record_message_type
class DIO(Message):
    message_type = MessageType.DIO

    @classmethod
    def parse(cls, flow):
        metric_value = int.from_bytes(flow[1:3], lrp.conf['endianess'])
        return cls(metric_value)

    def __init__(self, metric_value):
        self.metric_value = metric_value

    def dump(self):
        return super(DIO, self).dump() + self.metric_value.to_bytes(2, lrp.conf['endianess'])

    def __str__(self):
        return "%s <metric_value=%d>" % (self.__class__.__name__, self.metric_value)


@Message.record_message_type
class RREP(Message):
    message_type = MessageType.RREP

    @classmethod
    def parse(cls, flow):
        source = socket.inet_ntoa(flow[1:5])
        destination = socket.inet_ntoa(flow[5:9])
        hops = int.from_bytes(flow[9:11], lrp.conf['endianess'])
        return cls(source, destination, hops)

    def __init__(self, source, destination, hops):
        self.source = source
        self.destination = destination
        self.hops = hops

    def dump(self):
        result = b""
        result += socket.inet_aton(self.source)
        result += socket.inet_aton(self.destination)
        result += self.hops.to_bytes(2, lrp.conf['endianess'])
        return super(RREP, self).dump() + result

    def __str__(self):
        return "%s <source=%s destination=%s hops=%d>" % (self.message_type, self.source, self.destination, self.hops)
