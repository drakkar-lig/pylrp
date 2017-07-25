import logging
import socket
import struct

import click
import pyroute2
import pyroute2.netlink.rtnl.rtmsg

import lrp
import lrp.message


@click.command()
@click.argument("interface")
@click.argument("metric", default=2 ** 16 - 1)
@click.option("-v", "--verbose", count=True)
def main(interface, metric, verbose):
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    try:
        logging.basicConfig(format="[%(relativeCreated)d][%(levelname)s][%(name)s] %(message)s",
                            level=log_levels[verbose])
    except IndexError:
        raise Exception("Use at most %d --verbose flags" % (len(log_levels) - 1))

    with LrpProcess(interface, metric) as lrp:
        lrp.send_dio()
        lrp.wait_event()


class NeighborList:
    class Neighbor:
        pass

    pass


class LrpProcess:
    logger = logging.getLogger("LRP")

    own_metric = 2 ** 16 - 1

    def __init__(self, interface, own_metric=None):
        self.interface = interface
        with pyroute2.IPRoute() as ip:
            try:
                self.idx = ip.link_lookup(ifname=self.interface)[0]
            except IndexError:
                raise Exception("%s: unknown interface" % self.interface)
            try:
                self.own_ip = ip.get_addr(index=self.idx)[0].get_attr('IFA_ADDRESS')
            except IndexError:
                raise Exception("%s: interface has no IP address" % self.interface)
        if own_metric is not None:
            self.own_metric = own_metric
        self._successors = {}

    def __enter__(self):
        with pyroute2.IPRoute() as ip:
            iface_address = ip.get_addr(index=self.idx)[0].get_attr('IFA_ADDRESS')
        self.logger.debug("Guess %s's address is '%s'", self.interface, iface_address)
        iface_address_as_bytes = socket.inet_aton(iface_address)
        multicast_address_as_bytes = socket.inet_aton(lrp.conf['service_multicast_address'])

        self.logger.debug("Initialize output multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.bdc_out_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.bdc_out_socket.bind((self.own_ip, 0))
        self.bdc_out_socket.connect((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        self.logger.debug("Initialize input multicast socket ([%s]:%d)",
                          lrp.conf['service_multicast_address'], lrp.conf['service_port'])
        self.bdc_in_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.bdc_in_socket.setsockopt(socket.SOL_IP, socket.IP_ADD_MEMBERSHIP,
                                      struct.pack("=4s4s", multicast_address_as_bytes, iface_address_as_bytes))
        self.bdc_in_socket.bind((lrp.conf['service_multicast_address'], lrp.conf['service_port']))

        with pyroute2.IPDB() as ipdb:
            try:
                default_route = ipdb.routes['default']
                self.logger.info("Drop default route")  # should be set by the protocol itself
                default_route.remove().commit()
            except KeyError:
                # No default route, ok.
                pass

        return self

    def is_neighbor(self, address):
        # Check if neighbor is declared.
        address += "/32"
        with pyroute2.IPDB() as ipdb:
            if address not in ipdb.routes:
                # import pdb; pdb.set_trace()
                self.logger.info("Adding %s as neighbor" % address)
                ipdb.routes.add(dst=address, oif=self.idx,
                                scope=pyroute2.netlink.rtnl.rtscopes['RT_SCOPE_LINK'],
                                proto=pyroute2.netlink.rtnl.rtprotos['RTPROT_STATIC']) \
                    .commit()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logger.debug("Close service sockets")
        self.bdc_out_socket.close()
        self.bdc_in_socket.close()

    def wait_event(self):
        while True:
            data, (address, port) = self.bdc_in_socket.recvfrom(16)
            if address == self.own_ip:
                self.logger.debug("Skip a message from ourselves")
                continue
            msg = lrp.message.Message.parse(data)
            self.logger.info("Received %s from %s", msg, address)

            self.is_neighbor(address)

            route_cost = msg.metric_value + 1
            if msg.message_type == lrp.message.MessageType.DIO:
                if self.own_metric < route_cost:
                    self.logger.debug("Do not use DIO: route is too bad")
                    if self.own_metric + 2 < route_cost:
                        self.logger.info("Neighbor may be interested by our DIO")
                        self.send_dio()
                else:
                    with pyroute2.IPDB() as ipdb:
                        try:
                            with ipdb.routes['default'] as default_route:
                                self.logger.debug("Drop current default route")
                                default_route.remove()
                        except KeyError:
                            # No default route, ok.
                            pass

                        self._successors[address] = route_cost

                        if self.own_metric > route_cost:
                            self.logger.info("Update our metric to %d", route_cost)
                            self.own_metric = route_cost

                            self.logger.debug("Check if old successors are still usable")
                            for successor in list(self._successors.keys()):
                                if self._successors[successor] > self.own_metric:
                                    self.logger.info("Drop successor '%s': too high metric (was %d)", successor,
                                                     self._successors[successor])
                                    del self._successors[successor]

                            self.logger.debug("Inform neighbors that we have changed our metric")
                            self.send_dio()

                        if not len(self._successors) == 0:
                            ipdb.routes.add(dst="default", multipath=[{'gateway': key, 'hops': value} for key, value in
                                                                      self._successors.items()]).commit()

    def send_dio(self):
        dio = lrp.message.DIO(self.own_metric)
        self.logger.info("Send a %s", dio)
        self.bdc_out_socket.send(dio.dump())


if __name__ == "__main__":
    main()
