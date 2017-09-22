#!/usr/bin/env python
import glob
import logging
import os
import subprocess
import sys

import click
import docker
from docker.models.containers import Container

DEFAULT_NETWORK_NAME = "lrp_net_channel"
DEFAULT_IMAGE = "audeoudh/lrp:latest"
DEFAULT_EBTABLES_CHAIN_NAME = "lrp_net_channel"


class LrpContainer:
    def __init__(self, container_name, project_root, network, image=DEFAULT_IMAGE, is_sink=False):
        self.container_name = container_name
        self.project_root = project_root
        self.network = network
        self.image = image
        self.is_sink = is_sink

    def __enter__(self):
        # Compute the command for launching LRP
        command = "python -m lrp -vv daemon" + (" --metric 0 --sink" if self.is_sink else "")
        # Prepend the init script
        command = "/root/pylrp/docker_image/init_lrp.sh -v --wait " + command

        client = docker.from_env()
        logger.info("Start container %r", self.container_name)
        self.container = client.containers.run(
            image=self.image, volumes=["%s:%s:ro" % (self.project_root, '/root/pylrp')],
            working_dir="/root/pylrp/src", command=command, entrypoint="/root/pylrp/docker_image/init_lrp.sh",
            environment={'LANG': "fr_FR.UTF-8"}, network=self.network.network.name,
            name=self.container_name, hostname=self.container_name, privileged=True, detach=True, remove=True)
        self.network.add_container(self.container)

        logger.info("Start LRP daemon on %r", self.container.name)
        self.container.exec_run("touch /init_ready")

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self.container.kill()
            logger.info("Container %r stopped", self.container.name)
        except (docker.errors.NotFound, docker.errors.APIError):
            logger.info("Container %r already stopped", self.container.name)


class DockerAirNetwork:
    def __init__(self, network_name, chain_name=None):
        self.network_name = network_name
        self.chain_name = chain_name if chain_name is not None else "%s_rules" % network_name
        self.containers = {}
        self.is_allowed = set()

    def __enter__(self):
        # Create the docker network that simulates the air channel
        client = docker.from_env()
        try:
            # Take first network that matches this name
            self.network = client.networks.list(names=self.network_name)[0]
            logger.info("Reuse the existing network %r", self.network.name)
        except IndexError:
            # No network, create it
            self.network = client.networks.create(name=self.network_name)
            logger.info("Network %r created", self.network.name)

        # Create main ebtables rules
        logger.info("Create ebtables chain %r", self.chain_name)
        os.system("ebtables --new-chain %s" % self.chain_name)
        os.system("ebtables --policy %s DROP" % self.chain_name)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Delete ebtables rules
        logger.info("Remove ebtables chain %r", self.chain_name)
        for interface_name in self.containers.values():
            os.system("ebtables --delete FORWARD --out-interface %(iface)s --jump %(chain)s" %
                      dict(chain=self.chain_name, iface=interface_name))
        os.system("ebtables --delete-chain %s" % self.chain_name)

        # Delete docker network
        logger.info("Remove network %r", self.network.name)
        self.network.remove()

    def add_container(self, container: Container):
        # Add the container to the network
        try:
            self.network.connect(container)
        except docker.errors.APIError:
            # Should be already define into the network.
            pass

        # Get the host-end of the veth container interface
        interface_id = int(container.exec_run('cat /sys/class/net/eth0/iflink').decode('ascii'))
        ifindex_files = glob.glob("/sys/class/net/*/ifindex")
        interface_name = subprocess.run(["grep", "-l"] + ifindex_files + ["-e", str(interface_id)],
                                        stdout=subprocess.PIPE, check=True).stdout.decode("ascii").split("/")[4]
        self.containers[container] = interface_name

        # Prepare the filtering rules
        os.system("ebtables --append FORWARD --out-interface %(iface)s --jump %(chain)s" %
                  dict(chain=self.chain_name, iface=interface_name))

    def allow_comunication(self, c_from, c_to, two_sides=False):
        self.rights_of_communication(c_from, c_to, True)
        if two_sides:
            self.rights_of_communication(c_to, c_from, True)

    def deny_communication(self, c_from, c_to, two_sides=False):
        self.rights_of_communication(c_from, c_to, False)
        if two_sides:
            self.rights_of_communication(c_to, c_from, False)

    def rights_of_communication(self, c_from, c_to, can_communicate):
        if can_communicate and (c_from, c_to) not in self.is_allowed:
            self.is_allowed.add((c_from, c_to))
            os.system("ebtables --insert %(chain)s --out-interface %(from_if)s --in-interface %(to_if)s --jump ACCEPT" %
                      dict(chain=self.chain_name, from_if=self.containers[c_from.container],
                           to_if=self.containers[c_to.container]))
        elif not can_communicate and (c_from, c_to) not in self.is_allowed:
            self.is_allowed.discard((c_from, c_to))
            os.system("ebtables --delete %(chain)s --out-interface %(from_if)s --in-interface %(to_if)s --jump ACCEPT" %
                      dict(chain=self.chain_name, from_if=c_from.container.name, to_if=c_to.container.name))


@click.group()
def cli():
    pass


@cli.command()
@click.option("--project-root",
              default=os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0]))), show_default=True,
              help="Path to the project root.")
@click.option("--network-name", default=DEFAULT_NETWORK_NAME, show_default=True,
              help="Name of the docker network.")
@click.option("--ebtables-chain-name", default=DEFAULT_EBTABLES_CHAIN_NAME, show_default=True,
              help="Name of the ebtable chain to use")
def start(project_root, network_name, ebtables_chain_name):
    with DockerAirNetwork(network_name) as net:
        with LrpContainer("lrp_77", project_root, net) as container:
            with LrpContainer("lrp_00", project_root, net, is_sink=True) as sink:
                net.allow_comunication(sink, container, two_sides=True)

                # Stop, wait, and get CLI instructions
                import code
                code.interact(local=locals())
                pass


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")

    # Reduce docker logs
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    cli()
