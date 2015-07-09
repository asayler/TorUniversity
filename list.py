#!/usr/bin/env python3

import sys
import urllib.parse

import click
import onion_py.manager
import onion_py.caching


TLDS = ['edu']


def echo_table(values, headings=None, line_limit=None):

    # Preprocess
    values = [[str(c) for c in r] for r in values]

    # Calculate lengths
    if headings:
        len_tab = ([headings] + values)
    else:
        len_tab = values
    lengths = []
    for row in len_tab:
        for c in range(len(row)):
            if len(lengths) > c:
                if len(row[c]) > lengths[c]:
                    lengths[c] = len(row[c])
            else:
                lengths.append(len(row[c]))

    # Set Max Lengths
    if line_limit:
        # Calculate Max Lengths
        while sum(lengths) + (len(lengths) * 3) > line_limit:
            lengths[lengths.index(max(lengths))] -= 1
            if max(lengths) <= 4:
                break
        # Truncate Headings
        if headings:
            for c in range(len(headings)):
                if len(headings[c]) > lengths[c]:
                    headings[c] = headings[c][:(lengths[c]-3)] + "..."
        # Truncate Values
        for row in values:
            for c in range(len(row)):
                if len(row[c]) > lengths[c]:
                    row[c] = row[c][:(lengths[c]-3)] + "..."

    # Print Headings
    if headings:
        for c in range(len(lengths)):
            if c < len(headings):
                click.echo("{val:^{width}s} | ".format(val=headings[c], width=lengths[c]), nl=False)
            else:
                click.echo("{val:^{width}s} | ".format(val="", width=lengths[c]), nl=False)
        click.echo("")
        for c in range(len(lengths)):
            click.echo("{val:{fill}^{width}s} | ".format(val='-', fill='-', width=lengths[c]), nl=False)
        click.echo("")

    # Print Table
    for row in values:
        for c in range(len(lengths)):
            if c < len(row):
                click.echo("{val:>{width}s} | ".format(val=row[c], width=lengths[c]), nl=False)
            else:
                click.echo("{val:>{width}s} | ".format(val="", width=lengths[c]), nl=False)
        click.echo("")

def relay_sort_key(relay):
    hostname = relay.host_name.casefold()
    split = hostname.split('.')
    split.reverse()
    return '.'.join(split)

def analyze_relay(relay):

    # Check Hostname TLD
    if relay.host_name:
        clean_hostname = relay.host_name.casefold().strip()
        split_hostname = clean_hostname.split('.')
        tld = split_hostname[-1]
        if tld in TLDS:
            return True

def print_relays(relays):

    relays.sort(key=relay_sort_key)
    vals = []
    for relay in relays:
        vals.append([relay.host_name.casefold(), relay.nickname, relay.running, relay.contact])
    echo_table(vals, headings=['Hostname', 'Nickname', 'Running', 'Contact'], line_limit=160)


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

    click.echo("Exit Relays: ({:d} found)".format(len(exit_relays)))
    print_relays(exit_relays)
    click.echo("")

    click.echo("Middle Relays: ({:d} found)".format(len(middle_relays)))
    print_relays(middle_relays)
    click.echo("")

    click.echo("Guard Relays: ({:d} found)".format(len(guard_relays)))
    print_relays(guard_relays)
    click.echo("")

    click.echo("Other Relays: ({:d} found)".format(len(other_relays)))
    print_relays(other_relays)
    click.echo("")

    # Return exit status
    return 0

if __name__ == '__main__':
    sys.exit(list())
