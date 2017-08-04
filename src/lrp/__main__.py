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


if __name__ == "__main__":
    try:
        from lrp.linux_wrapper import daemon

        cli.add_command(daemon)
    except ImportError:
        pass

    try:
        from lrp.sniffer import sniff

        cli.add_command(sniff)
    except ImportError:
        pass

    cli()
