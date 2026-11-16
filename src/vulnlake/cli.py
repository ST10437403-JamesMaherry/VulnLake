"""Command-line interface for VulnLake pipeline operations."""

import argparse

from vulnlake.config import settings
from vulnlake.ingestion.cisa import ingest_cisa_kev
from vulnlake.ingestion.epss import ingest_epss


def build_parser() -> argparse.ArgumentParser:
    """Create and configure the VulnLake command-line argument parser.

    The CLI provides one explicit command per ingestion source while keeping
    command execution separate from the source-specific implementation.
    """

    parser = argparse.ArgumentParser(
        prog="vulnlake",
        description="VulnLake vulnerability intelligence data pipeline.",
    )

    # Each ingestion source is exposed as a subcommand:
    #
    # vulnlake ingest-cisa
    # vulnlake ingest-epss
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    # CISA Known Exploited Vulnerabilities ingestion command.
    subparsers.add_parser(
        "ingest-cisa",
        help="Ingest the CISA KEV catalog into the Bronze layer.",
    )

    # FIRST Exploit Prediction Scoring System ingestion command.
    subparsers.add_parser(
        "ingest-epss",
        help="Ingest the FIRST EPSS daily score set into the Bronze layer.",
    )

    return parser


def main() -> None:
    """Execute the requested VulnLake CLI command.

    Every ingestion function returns the same normalized SourceRun model.
    This means the CLI can serialize results in one consistent format
    regardless of which upstream source produced them.
    """

    parser = build_parser()
    args = parser.parse_args()

    # Dispatch the selected command to its source-specific ingestion pipeline.
    if args.command == "ingest-cisa":
        run = ingest_cisa_kev(settings)

    elif args.command == "ingest-epss":
        run = ingest_epss(settings)

    else:
        # argparse currently prevents unsupported values from reaching this
        # point, but this guard protects the CLI if command handling changes
        # in the future.
        parser.error(f"Unsupported command: {args.command}")

    # SourceRun is serialized as JSON so local users, CI workflows, logging
    # systems and future orchestration can consume the result consistently.
    print(run.model_dump_json(indent=2))


if __name__ == "__main__":
    # Allow execution using:
    #
    # python -m vulnlake.cli <command>
    #
    # The pyproject.toml console entry point also exposes the shorter:
    #
    # vulnlake <command>
    main()
