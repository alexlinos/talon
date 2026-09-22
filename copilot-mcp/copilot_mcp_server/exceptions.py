"""Custom exceptions for the CoPilot MCP Server."""


class CoPilotMCPError(Exception):
    """Base exception for CoPilot MCP Server."""


class CoPilotAuthenticationError(CoPilotMCPError):
    """Raised when authentication with CoPilot fails."""


class CoPilotTwoFactorRequiredError(CoPilotAuthenticationError):
    """Raised when the CoPilot account requires 2FA, which is unsupported."""


class CoPilotAPIError(CoPilotMCPError):
    """Raised when the CoPilot API returns an error response."""


class ConfigurationError(CoPilotMCPError):
    """Raised when configuration is invalid or incomplete."""
