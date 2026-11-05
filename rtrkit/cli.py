"""Command line entry point for rtrkit.

The CLI is how most people meet a protocol library, so it is part of the public surface and
gets the same typing and testing discipline as the rest of the package.
"""

from __future__ import annotations

import argparse
import sys

USAGE = """\
Examples:
  rtrkit serve --listen 127.0.0.1:8323 -- source a store and watch routers attach"""


def build_parser():
    return argparse.ArgumentParser(
        prog="rtrkit",
        description="RPKI-to-Router (RTR) version 0 and 1: cache server and router client, IPv4 and IPv6 prefix and router-key records, serial notify and reset query",
        epilog=USAGE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )


def main(argv=None):
    """Parse arguments, then refuse to pretend the protocol works.

    Exiting non-zero is the correct behaviour for a shell. A CLI that printed a friendly
    banner and exited 0 would be indistinguishable from one that actually did something.
    """
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_usage(sys.stderr)
    print("rtrkit: no protocol behaviour is implemented yet; see ROADMAP.md", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
