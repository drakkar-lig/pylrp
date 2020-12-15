# Copyright Laboratoire d'Informatique de Grenoble (2017)
#
# This file is part of pylrp.
#
# Pylrp is a Python/Linux implementation of the LRP routing protocol.
#
# This software is governed by the CeCILL license under French law and
# abiding by the rules of distribution of free software.  You can  use,
# modify and/ or redistribute the software under the terms of the CeCILL
# license as circulated by CEA, CNRS and INRIA at the following URL
# "http://www.cecill.info".
#
# As a counterpart to the access to the source code and  rights to copy,
# modify and redistribute granted by the license, users are provided only
# with a limited warranty  and the software's author,  the holder of the
# economic rights,  and the successive licensors  have only  limited
# liability.
#
# In this respect, the user's attention is drawn to the risks associated
# with loading,  using,  modifying and/or developing or reproducing the
# software by the user in light of its specific status of free software,
# that may mean  that it is complicated to manipulate,  and  that  also
# therefore means  that it is reserved for developers  and  experienced
# professionals having in-depth computer knowledge. Users are therefore
# encouraged to load and test the software's suitability as regards their
# requirements in conditions enabling the security of their systems and/or
# data to be ensured and,  more generally, to use and operate it in the
# same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL license and that you accept its terms.

import logging

import click


@click.group()
@click.option("-v", "--verbose", count=True)
def cli(verbose):
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    try:
        logging.basicConfig(format="[%(relativeCreated)d][%(levelname)s][%(name)s] %(message)s",
                            level=log_levels[verbose])
    except IndexError:
        raise Exception("Use at most %d --verbose flags" % (len(log_levels) - 1))


def _unavailable_subcommand(import_exception):
    def unavailable(**kwargs):
        raise import_exception

    unavailable.__doc__ = """This command is not available: %s""" % import_exception.args
    unavailable = click.command()(unavailable)
    unavailable = click.argument("", nargs=1)(unavailable)
    return unavailable


if __name__ == "__main__":
    try:
        from lrp.linux_wrapper import daemon

        cli.add_command(daemon)
    except ImportError as e:
        cli.add_command(_unavailable_subcommand(e), name="daemon")

    try:
        from lrp.sniffer import sniff

        cli.add_command(sniff)
    except ImportError as e:
        cli.add_command(_unavailable_subcommand(e), name="sniff")

    cli()
