import logging
import os
import sys
from contextlib import contextmanager

import click
import docker

DEFAULT_NETWORK_NAME = "lrp_net_channel"
DEFAULT_IMAGE = "audeoudh/lrp:latest"


def docker_run(container_name, network, project_root, image=DEFAULT_IMAGE, is_sink=False):
    """Starts a docker container, with the LRP process started into."""
    client = docker.from_env()
    command = "python -m lrp -vv daemon" + (" --metric 0 --sink" if is_sink else "")
    client.containers.run(image=image, command=command,
                          network=network, volumes=["%s:%s:ro" % (project_root, '/root/pylrp')],
                          name=container_name, hostname=container_name,
                          entrypoint="/root/pylrp/docker_image/init_lrp.sh", working_dir="/root/pylrp/src",
                          environment={'LANG': "fr_FR.UTF-8"},
                          privileged=True, detach=True, remove=True)


@contextmanager
def docker_network(network):
    """Create the docker network and prune it at the end."""
    client = docker.from_env()
    client.networks.create(name=network)
    yield network
    client.networks.prune()  # .remove(name=network) would be better; but it does not exists


@click.group()
def cli():
    pass


@cli.command()
@click.option("--project-root",
              default=os.path.dirname(os.path.dirname(os.path.realpath(sys.argv[0]))), show_default=True,
              help="Path to the project root.")
@click.option("--network-name", default=DEFAULT_NETWORK_NAME, show_default=True,
              help="Name of the docker network.")
def start(project_root, network_name):
    logger.info("Start network %s", network_name)
    with docker_network(network_name):
        container_name = "lrp_77"
        logger.info("Start container %s", container_name)
        docker_run(container_name, network_name, project_root)


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    cli()
