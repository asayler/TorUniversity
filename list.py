#!/usr/bin/env python3

import sys

import click
import onion_py.manager

@click.command()
def list():
    """List University-Affiliated Tor Nodes"""

    manager = onion_py.manager.Manager()

    click.echo("Querying OnionOO for list of relays...")
    details = manager.query('details')

    relays = details.relays
    click.echo("Analyzing {:d} relays...".format(len(relays)))

    return 0

if __name__ == '__main__':
    sys.exit(list())
