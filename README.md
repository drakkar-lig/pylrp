PyLRP — A python implementation of the Lightweight Routing Protocol
===================================================================

## Python architecture

PyLRP is proposed as a package. You can install it by using the `setup.py` 
script.

The package can be directly called from command-line. Run
`python -m lrp --help` to get help on its usage. Provided command-line tools 
are:

* `sniff`: kind of tcpdump sniffer; however, it displays only LRP messages, 
correctly formatted.

* `daemon`: the LRP daemon itself. Currently, this command is mapped to 
`LinuxLrpProcess`, as it is the only concrete `LrpProcess` subclass we have.



## Supported plateforms

Currently, **only linux with netlink and netfilter installed is supported**. 
However, the core of the protocol is available through an independent python 
abstract class: `lrp.daemon.LrpProcess`. To make it compliant with another 
platform, one should subclass it, as `lrp.linux_wrapper.LinuxLrpProcess` do.


### Configuration of linux system

The host route packets through the interface from which the packet has come. 
Obviously, it sends ICMP Redirect messages. However, we simulate a multi-hop 
wireless network. We need to deactivate this: 
`sysctl net.ipv4.conf.{eth0,default,all}.send_redirects=0`.

Reverse-path filter drops packets coming from a host towards which we do not 
have a route. If we can't answer, we drop. As the routing process itself does 
not necessarily have a route towards an unknown node (and, at start, it does 
not have a route at all), we must accept this kind of packets: 
`sysctl net.ipv4.conf.{eth0,default,all}.rp_filter=0`.



## Testing

Tests are docker-based (so, obviously, docker is expected to be installed on
this machine). A docker image is provided, and test can be run from a python
script.


### The docker image

A Dockerfile is provided in `tests/docker_image/`. Just build it:

    docker build -t "$IMAGE_NAME"


### Run a container

To run LRP with its own network stack, I use this command:

    docker run --network "$NETWORK_NAME" \
               --volume "${PROJECT_ROOT}:/root/pylrp:ro" \
               --privileged \
               --name "CONTAINER_$NAME" --hostname "$CONTAINER_NAME" \
               --entrypoint '/root/pylrp/docker_image/init_lrp.sh' \
               --workdir /root/pylrp/src \
               --env LANG=fr_FR.UTF-8 \
               --interactive --tty \
               "$IMAGE_NAME" \
               python -m lrp -v daemon

Optionally, for the sink, add `--metric 0 --sink` to the last line.

To have a bash prompt on top of this node, e.g. to be able to see the
routing table / to ping other machines, use:

    docker exec -it "$CONTAINER_NAME" /bin/bash

To get the logs of the daemon, use:

    docker logs "$CONTAINER_NAME"


### Setting the network topology

If you launch many containers (in the same network), you should be able to
route packets from a container to another. However, it won't be a real 
multi-hop network, as all communications between containers are allowed.

To limit the connectivity between containers, use `ebtables`:

1. Redirect all simulation specific traffic to a special table:
   
       ebtables -N "$NETWORK_NAME"
       ebtables -A FORWARD -i veth<xxxx> -j "$NETWORK_NAME"
   
   (the second line is to be applied to each host-side virtual-ethernet
   interface linked to the docker containers).
   
2. Drop all traffic reaching this table:

       ebtables -P "$NETWORK_NAME" DROP

3. Allow traffic between some specific containers (bidirectionnaly):

       ebtables -A "$NETWORK_NAME" -i veth<xxxx> -o veth<yyyy> -j ACCEPT
       ebtables -A "$NETWORK_NAME" -i veth<yyyy> -o veth<xxxx> -j ACCEPT

4. Optionally, allow the sink to communicate with the host:
   
       ebtables -A "$NETWORK_NAME" -i veth<sinkxx> -o br-<xxxx> -j ACCEPT


### Automated testing

All these steps above (build image, launch container & configure network
topology) are implemented in python, in the `tests/launch_dockers.py` script.
Launch it using:

    python tests/launch_dockers.py test
