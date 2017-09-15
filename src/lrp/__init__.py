conf = {
    'endianess': "big",
    'service_multicast_address': "224.0.0.120",
    'service_port': 6666,

    # Interval in s between DIO emission, when the node is disconnected.
    'dio_reconnect_interval': 10,
    'dio_delay': 1,

    # netlink-related configuration
    'netlink': {
        # RTPROT number for LRP. See `man rtnetlink.7`
        'proto_number': 43,
        # Number of the netfilter queue where non-routables are sent
        'netfilter_queue_nb': 43,
    }
}
