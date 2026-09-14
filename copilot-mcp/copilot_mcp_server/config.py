"""Configuration management for the CoPilot MCP Server."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List

from copilot_mcp_server.exceptions import ConfigurationError


def _str_to_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class CoPilotConfig:
    """Connection settings for the CoPilot backend."""

    url: str = ""
    username: str = ""
    password: str = ""
    ssl_verify: bool = True
    timeout: int = 30

    @classmethod
    def from_env(cls, prefix: str = "COPILOT") -> "CoPilotConfig":
        return cls(
            url=os.getenv(f"{prefix}_URL", "").rstrip("/"),
            username=os.getenv(f"{prefix}_USERNAME", ""),
            password=os.getenv(f"{prefix}_PASSWORD", ""),
            ssl_verify=_str_to_bool(os.getenv(f"{prefix}_SSL_VERIFY", "true")),
            timeout=int(os.getenv(f"{prefix}_TIMEOUT", "30")),
        )

    def validate(self) -> None:
        missing = [
            name
            for name, value in (
                ("COPILOT_URL", self.url),
                ("COPILOT_USERNAME", self.username),
                ("COPILOT_PASSWORD", self.password),
            )
            if not value
        ]
        if missing:
            raise ConfigurationError(
                f"Missing required CoPilot configuration: {', '.join(missing)}"
            )


@dataclass
class ServerConfig:
    """MCP server runtime settings."""

    log_level: str = "INFO"
    disabled_tools: List[str] = field(default_factory=list)
    disabled_categories: List[str] = field(default_factory=list)
    read_only: bool = False

    @classmethod
    def from_env(cls) -> "ServerConfig":
        disabled_tools = [
            t.strip() for t in os.getenv("COPILOT_DISABLED_TOOLS", "").split(",") if t.strip()
        ]
        disabled_categories = [
            c.strip() for c in os.getenv("COPILOT_DISABLED_CATEGORIES", "").split(",") if c.strip()
        ]
        return cls(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            disabled_tools=disabled_tools,
            disabled_categories=disabled_categories,
            read_only=_str_to_bool(os.getenv("COPILOT_READ_ONLY", "false")),
        )


@dataclass
class Config:
    """Top-level configuration combining CoPilot and server settings."""

    copilot: CoPilotConfig
    server: ServerConfig

    @classmethod
    def from_env(cls) -> "Config":
        return cls(copilot=CoPilotConfig.from_env(), server=ServerConfig.from_env())

    def validate(self) -> None:
        self.copilot.validate()

    def setup_logging(self) -> None:
        logging.basicConfig(
            level=getattr(logging, self.server.log_level.upper(), logging.INFO),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
