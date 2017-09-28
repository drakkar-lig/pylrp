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
        # Number of the netfilter queue where non-routables from loop-avoidance mechanism are sent
        'netfilter_queue_nb': 43,
        # Name of the iptables chain owning the LRP rules
        'iptables_chain_name': "LRP_RULES",
    }
}
