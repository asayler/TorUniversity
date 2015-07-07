#!/usr/bin/env python3

import sys
import urllib.parse

import click
import onion_py.manager
import onion_py.caching


TLDS = ['edu']

def analyze_relay(relay):

    # Check TLD
    if relay.host_name:
        clean_hostname = relay.host_name.casefold().strip()
        split_hostname = clean_hostname.split('.')
        tld = split_hostname[-1]
        if tld in TLDS:
            return True

@click.command()
def list():
    """List University-Affiliated Tor Nodes"""

    # Setup OnionOO Module
    cache = onion_py.caching.OnionSimpleCache()
    manager = onion_py.manager.Manager(cache)

    # Query OnionOO
    click.echo("Querying OnionOO for list of relays...")
    details = manager.query('details')

    # Check relays for matches
    relays = details.relays
    click.echo("Analyzing {:d} relays...".format(len(relays)))
    for relay in relays:
        match = analyze_relay(relay)
        if match:
            click.echo("{:s}".format(relay.host_name.casefold()))

    # Return exit status
    return 0

if __name__ == '__main__':
    sys.exit(list())
