#!/usr/bin/env python
import glob
import logging
import os
import subprocess
import time

import click
import docker, docker.errors
import networkx
from docker.models.containers import Container

DEFAULT_NETWORK_NAME = "lrp_net_channel"
DEFAULT_IMAGE = "audeoudh/lrp:latest"
DEFAULT_EBTABLES_CHAIN_NAME = "lrp_net_channel"
DEFAULT_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


class DockerBasedWSN:
    """A Wireless Sensors Network model, based on docker containers.

    The topology of the WSN is defined by a networkx.DiGraph. Nodes and edges
    are defined there."""

    def __init__(self, topology: networkx.DiGraph,
                 docker_network_name=None, ebtables_chain_name=None, project_root=DEFAULT_PROJECT_ROOT):
        super().__init__()

        self.topology = topology
        self.docker_net_name = docker_network_name if docker_network_name is not None \
            else "%s_network" % (topology.name if topology.name != '' else self.__class__.__name__)
        self.ebtables_chain_name = ebtables_chain_name if ebtables_chain_name is not None \
            else "%s_rules" % (topology.name if topology.name != '' else self.__class__.__name__)
        self.project_root = project_root

        self._docker_client = docker.from_env()
        self._containers = {}

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()

    def start(self):
        self._ebtables_init()
        self._docker_net_init()

        for node, node_attrs in self.topology.nodes(data=True):
            self._containers[node] = self._docker_container_start(
                container_name=node, image=node_attrs.get('docker_image', DEFAULT_IMAGE),
                is_sink=node_attrs.get('is_sink', False))

        for node in self.topology.nodes():
            for neighbor in self.topology.neighbors(node):
                _, from_if = self._containers[node]
                _, to_if = self._containers[neighbor]
                self._ebtables_add_edge(from_if, to_if)

    def stop(self):
        self._ebtables_clean()
        for container_name in self._containers.keys():
            self._docker_container_stop(container_name)
        self._docker_net_clean()

    def _docker_net_init(self):
        """Initialize the docker network."""
        try:
            self._network = self._docker_client.networks.list(names=[self.docker_net_name])[0]
            logger.info("Reusing docker network %r", self._network.name)
        except IndexError:
            logger.info("Create docker network %r", self.docker_net_name)
            self._network = self._docker_client.networks.create(name=self.docker_net_name)

    def _docker_net_clean(self):
        """Clean the docker network."""
        logger.info("Remove network %r", self._network.name)
        for container in self._network.containers:
            self._network.disconnect(container)
        self._network.remove()

    def _ebtables_init(self):
        """Initialize the ebtables chain & rules."""
        logger.info("Create ebtables chain %r", self.ebtables_chain_name)
        subprocess.run(("ebtables --new-chain %s" % self.ebtables_chain_name).split())
        subprocess.run(("ebtables --policy %s DROP" % self.ebtables_chain_name).split(), check=True)

    def _ebtables_clean(self):
        """Clean the ebtables chain & rules."""
        logger.info("Remove ebtables chain %r", self.ebtables_chain_name)
        for _, interface_name in self._containers.values():
            subprocess.run(("ebtables --delete FORWARD --out-interface %(iface)s --jump %(chain)s" %
                            dict(chain=self.ebtables_chain_name, iface=interface_name)).split())
        subprocess.run(("ebtables --delete-chain %s" % self.ebtables_chain_name).split())

    def _ebtables_init_node(self, iface):
        """Set ebtables initial rule for this container."""
        subprocess.run(("ebtables --append FORWARD --out-interface %(iface)s --jump %(chain)s" %
                        dict(chain=self.ebtables_chain_name, iface=iface)).split(), check=True)

    def _ebtables_add_edge(self, from_if, to_if):
        """Allow from_if to send messages to to_if."""
        subprocess.run(("ebtables --delete %(chain)s --out-interface %(from_if)s --in-interface %(to_if)s "
                        "--jump ACCEPT" % dict(chain=self.ebtables_chain_name, from_if=from_if, to_if=to_if)).split(),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(("ebtables --insert %(chain)s --out-interface %(from_if)s --in-interface %(to_if)s "
                        "--jump ACCEPT" % dict(chain=self.ebtables_chain_name, from_if=from_if, to_if=to_if)).split(),
                       check=True)

    def _ebtables_drop_edge(self, from_if, to_if):
        """Disallow from_if to send messages to to_if."""
        raise NotImplementedError

    def _docker_container_start(self, container_name, image, is_sink=False):
        # Compute the command for launching LRP
        command = "python -m lrp -vv daemon" + (" --metric 0 --sink" if is_sink else "")
        # Prepend the init script
        command = "/root/pylrp/tests/docker_image/init_lrp.sh -v --wait " + command

        try:
            container = self._docker_client.containers.run(
                image=image, volumes=["%s:%s:ro" % (self.project_root, '/root/pylrp')],
                environment={'LANG': "fr_FR.UTF-8"}, network=self._network.name,
                working_dir="/root/pylrp/src", command=command, entrypoint="/root/pylrp/tests/docker_image/init_lrp.sh",
                name=container_name, hostname=container_name, privileged=True, detach=True, remove=True)
            logger.info("Container %r created%s", container_name, " as a sink" if is_sink else "")
        except docker.errors.APIError as e:
            if e.status_code == 409:  # Conflict
                # Try to use the container if it is already created
                try:
                    container = self._docker_client.containers.get(container_name)
                    if container.status not in ('created', 'exited'):
                        raise Exception("Not handled stat %r for the container %r" %
                                        (container.status, container_name))
                except docker.errors.NotFound:
                    # No such container
                    raise Exception("Unable to create nor get the container %r" % container_name, e)
                else:
                    # Starting the container
                    container.start()
                    logger.info("Container %r restarted", container_name)
            else:
                raise

        # Get the host-end of the veth container interface
        interface_id = int(container.exec_run('cat /sys/class/net/eth0/iflink').decode('ascii'))
        ifindex_files = glob.glob("/sys/class/net/*/ifindex")
        interface_name = subprocess.run(["grep", "-l"] + ifindex_files + ["-e", str(interface_id)],
                                        stdout=subprocess.PIPE, check=True).stdout.decode("ascii").split("/")[4]

        self._ebtables_init_node(interface_name)

        logger.info("Start LRP daemon on %r", container.name)
        container.exec_run("touch /init_ready")

        return container, interface_name

    def _docker_container_stop(self, container_name):
        container, _ = self._containers[container_name]
        try:
            container.kill()
            logger.info("Container %r stopped", container.name)
        except (docker.errors.NotFound, docker.errors.APIError):
            logger.info("Container %r already stopped", container_name)


def exec_with_rc(container: Container, cmd):
    """Execute command on a container and get its return code.

    The command is executed in the same way `container.exec_run` would do,
    but stdout and stderr are discarded and the function return its exit code."""
    client = docker.from_env()
    exec_id = client.api.exec_create(container.id, cmd, stdout=False, stderr=False)['Id']
    client.api.exec_start(exec_id, detach=False)

    response = client.api.exec_inspect(exec_id)

    # Fix: wait for the command to finish. With detach=False, docker-py should wait for it to finish, but it does not…
    while response['Running']:
        time.sleep(0.5)
        response = client.api.exec_inspect(exec_id)

    return response['ExitCode']


def build_image(dockerfile_path, tag=DEFAULT_IMAGE, **kwargs):
    """Build a docker image"""
    client = docker.from_env()
    logger.info("Build image %r from %r" % (tag, dockerfile_path))
    client.images.build(path=dockerfile_path, tag=tag, **kwargs)


def connectivity_matrix(nodes: list, ping_count=2):
    """Test connectivity between all nodes.

    :param nodes: the set of container names that should be tested
    :param ping_count: the number of ping probes to send"""
    client = docker.from_env()
    print(" " * 5 + "".join(" {:^5}".format(n) for n in nodes))
    for from_node in nodes:
        if not isinstance(from_node, Container):
            from_node = client.containers.get(from_node)
        print("{:^5}".format(from_node.name), end="")
        for to_node in nodes:
            if from_node.name == to_node:
                print(" " * (5 + 1), end="")
            else:
                if isinstance(to_node, Container):
                    to_node = to_node.name
                ok = exec_with_rc(from_node, ["ping", "-c", str(ping_count), to_node]) == 0
                print(" {:^5}".format("✔" if ok else "✗"), end="", flush=True)
        print()


@click.group()
def cli():
    pass


@cli.command()
@click.option("--interact/--no-interact", default=False, show_default=True,
              help="Interact when the containers and the network are started.")
@click.option("--test-connectivity/--no-test-connectivity", default=True, show_default=True,
              help="Test connectivity between nodes when the containers and the network are started")
def test(interact=False, test_connectivity=True):
    """Run some automated tests.

    * Start the containers
    * Configure the network
    * Test connectivity between containers
    * Stop all of them"""
    # Create network topology
    topology = networkx.Graph()
    topology.add_edges_from((("lrp_1", "lrp_2"),
                             ("lrp_2", "lrp_3"), ("lrp_2", "lrp_4"),
                             ("lrp_3", "lrp_5"), ("lrp_3", "lrp_6"),
                             ("lrp_4", "lrp_6")))
    topology.add_node("lrp_1", is_sink=True)

    # Ensure the image is correctly built
    build_image(os.path.join(DEFAULT_PROJECT_ROOT, "tests", "docker_image"))

    # Start dockers & LRP daemons
    with DockerBasedWSN(topology.to_directed(),
                        docker_network_name=DEFAULT_NETWORK_NAME,
                        project_root=DEFAULT_PROJECT_ROOT) as net:
        logger.info("Wait for the routing protocol's initialization…")
        time.sleep(10)

        if test_connectivity:
            connectivity_matrix(topology.nodes())

        if interact:
            import code
            vars = dict(locals())
            vars.update(globals())
            code.interact(local=vars)
            pass


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG, format="[%(levelname)s] %(message)s")

    # Reduce docker logs
    logging.getLogger("docker").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    cli()
