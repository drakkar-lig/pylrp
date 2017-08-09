#!/usr/bin/env bash
#
# Init system for LRP: configure network, allow routing, drop default configuration,...

# Logging utility. Launch with `-v` to see the logs.
if [ "$1" = "-v" ]; then
    log() {
        echo "[INIT] ${@}"
    }
    shift  # Eat '-v'
else
    log(){ :;}
fi

log Initialize system
NETWORK_INTERFACE=eth0
SYSCTL_INTERFACES=("${NETWORK_INTERFACE}" all default)

log Configure sys
for interface in "${SYSCTL_INTERFACES[@]}"; do
    # Nodes are on the same sub-network, but they cannot always communicate: we
    # are in ad-hoc mode. Disable ICMP-redirects, as they are in fact false.
    sysctl net.ipv4.conf.${interface}.send_redirects=0 > /dev/null
    # Drop reverse-path filter: we must receive packets from a node we did not
    # know before.
    sysctl net.ipv4.conf.${interface}.rp_filter=0 > /dev/null
done

# We cannot communicate with all nodes in the subnet. Disable the general
# on-link status, and configure the interface to be on a /32 network.
OLD_IP="$(ip address show dev "${NETWORK_INTERFACE}" | grep inet | grep '[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*/[0-9]*' -o)"
ip address delete "${OLD_IP}" dev "${NETWORK_INTERFACE}"
log "${OLD_IP} dropped"
NEW_IP="$(sed 'sW\(.*\)/.*W\1/32W' <<< "${OLD_IP}")"
ip address add "${NEW_IP}" dev "${NETWORK_INTERFACE}"
log "${NEW_IP} set"

# Wait for container be ready to start
read -p "System initialized. Press enter to continue" foo

# Chain the next command
exec "$@"
