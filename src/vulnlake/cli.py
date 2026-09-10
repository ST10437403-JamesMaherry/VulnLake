"""Command-line interface for VulnLake pipeline operations."""

import argparse

from vulnlake.config import settings
from vulnlake.ingestion.cisa import ingest_cisa_kev


def build_parser() -> argparse.ArgumentParser:
    """Create the VulnLake command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="vulnlake",
        description="VulnLake vulnerability intelligence data pipeline.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # Day 1 ingestion command.
    subparsers.add_parser(
        "ingest-cisa",
        help="Ingest the CISA KEV catalog into the Bronze layer.",
    )

    return parser


def main() -> None:
    """Execute a VulnLake CLI command."""

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "ingest-cisa":
        run = ingest_cisa_kev(settings)

        # The run summary is intentionally machine-readable.
        print(run.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
