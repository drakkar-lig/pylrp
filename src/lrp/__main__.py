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
