#!/usr/bin/env python3

import sys
import urllib.parse

import click
import onion_py.manager
import onion_py.caching


TLDS = ['edu']

def analyze_relay(relay):

    # Check Hostname TLD
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
    matched = []
    for relay in relays:
        match = analyze_relay(relay)
        if match:
            matched.append(relay)

    # Post process
    exit_relays = []
    middle_relays = []
    guard_relays = []
    other_relays = []
    for relay in matched:
        placed = False
        if relay.exit_probability and (relay.exit_probability > 0):
            exit_relays.append(relay)
            placed = True
        if relay.middle_probability and (relay.middle_probability > 0):
            middle_relays.append(relay)
            placed = True
        if relay.guard_probability and (relay.guard_probability > 0):
            guard_relays.append(relay)
            placed = True
        if not placed:
            other_relays.append(relay)

    # Display Relays
    click.echo("")
    exit_relays.sort(key=lambda x: x.host_name.casefold())
    middle_relays.sort(key=lambda x: x.host_name.casefold())
    guard_relays.sort(key=lambda x: x.host_name.casefold())
    other_relays.sort(key=lambda x: x.host_name.casefold())

    click.echo("Exit Relays: ({:d} found)".format(len(exit_relays)))
    for relay in exit_relays:
        click.echo("{:s}".format(relay.host_name.casefold()))
    click.echo("")

    click.echo("Middle Relays: ({:d} found)".format(len(middle_relays)))
    for relay in middle_relays:
        click.echo("{:s}".format(relay.host_name.casefold()))
    click.echo("")

    click.echo("Guard Relays: ({:d} found)".format(len(guard_relays)))
    for relay in guard_relays:
        click.echo("{:s}".format(relay.host_name.casefold()))
    click.echo("")

    click.echo("Other Relays: ({:d} found)".format(len(other_relays)))
    for relay in other_relays:
        click.echo("{:s}".format(relay.host_name.casefold()))
    click.echo("")

    # Return exit status
    return 0

if __name__ == '__main__':
    sys.exit(list())
