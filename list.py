#!/usr/bin/env python3

import sys

import click
import onion_py

@click.command()
def list():
    """List University-Affiliated Tor Nodes"""

    return 0

if __name__ == '__main__':
    sys.exit(list())
