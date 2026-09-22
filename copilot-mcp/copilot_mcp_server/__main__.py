"""CLI entry point for the CoPilot MCP Server."""

from __future__ import annotations

import argparse
import logging
import sys

from dotenv import load_dotenv

from copilot_mcp_server import __version__
from copilot_mcp_server.config import Config
from copilot_mcp_server.server import CoPilotMCPServer

logger = logging.getLogger(__name__)


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="copilot-mcp-server",
        description="SOCFortress CoPilot MCP Server",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("--copilot-url", default=None, help="CoPilot backend base URL")
    parser.add_argument("--copilot-username", default=None, help="CoPilot service account username")
    parser.add_argument("--copilot-password", default=None, help="CoPilot service account password")
    parser.add_argument(
        "--copilot-ssl-verify",
        default=None,
        help="Verify TLS certificates ('true' or 'false')",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main() -> None:
    load_dotenv()

    args = create_parser().parse_args()
    config = Config.from_env()

    if args.copilot_url:
        config.copilot.url = args.copilot_url.rstrip("/")
    if args.copilot_username:
        config.copilot.username = args.copilot_username
    if args.copilot_password:
        config.copilot.password = args.copilot_password
    if args.copilot_ssl_verify is not None:
        config.copilot.ssl_verify = args.copilot_ssl_verify.strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if args.log_level:
        config.server.log_level = args.log_level

    config.validate()
    config.setup_logging()

    server = CoPilotMCPServer(config)
    server.start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
        sys.exit(0)
    except Exception as exc:  # noqa: BLE001
        logger.error("Server error: %s", exc)
        sys.exit(1)
