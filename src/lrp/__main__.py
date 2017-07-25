import logging

import click

from lrp.daemon import daemon


@click.group()
@click.option("-v", "--verbose", count=True)
def cli(verbose):
    log_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
    try:
        logging.basicConfig(format="[%(relativeCreated)d][%(levelname)s][%(name)s] %(message)s",
                            level=log_levels[verbose])
    except IndexError:
        raise Exception("Use at most %d --verbose flags" % (len(log_levels) - 1))


cli.add_command(daemon)

if __name__ == "__main__":
    cli()
