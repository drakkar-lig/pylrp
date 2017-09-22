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

# Use `--wait` to make init script waiting before chaining with the next
# command. To unlock it, just touch the file `/init_ready`. Useful if external
# configuration is needed before the machine starts.
if [ "$1" = "--wait" ]; then
    shift  # Eat '--wait'
    log "Wait for \`/init_ready\`"
    while [ ! -e /init_ready ]; do
        sleep 1
    done
    rm /init_ready
fi

# Chain the next command
log "Launch $1"
exec "$@"
