# server/core/secrets_config.py
"""
VaultMind Enterprise Secrets Governance Module
Centralizes loading, validation, masking, and environment checks for sensitive operational credentials.
Prevents unredacted keys from being logged and enforces strict checks in production environments.
"""
import os
import logging
from typing import Optional, List
from dotenv import load_dotenv

# Load local .env file if present
load_dotenv()

# Setup structured logger
logger = logging.getLogger("VaultMindSecrets")


class SecretsManager:
    """Central singleton for accessing and validating application secrets and environment settings."""

    def __init__(self):
        self.env = os.getenv("VAULTMIND_ENV", "development").lower()
        self._validate_critical_secrets()

    def get(self, key: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
        """Retrieve a secret by key. If required is True and key is missing/placeholder, raises ValueError in production."""
        val = os.getenv(key, default)

        if required and not val:
            msg = f"[SecretsManager] Critical secret '{key}' is not set."
            if self.env == "production":
                raise ValueError(f"FATAL: {msg} Server cannot start in production mode without '{key}'.")
            else:
                logger.warning(f"{msg} Using default/fallback behavior for development.")

        # Check if val is a placeholder (e.g. YOUR_API_KEY_HERE)
        if val and ("YOUR_" in val or "_HERE" in val):
            if self.env == "production":
                raise ValueError(f"FATAL: Secret '{key}' contains a placeholder string in production environment.")
            else:
                logger.warning(f"[SecretsManager] Secret '{key}' appears to be a placeholder: '{val}'")

        return val

    def get_int(self, key: str, default: int) -> int:
        """Safely retrieve integer configuration."""
        val = self.get(key)
        if val is None:
            return default
        try:
            return int(val)
        except ValueError:
            logger.error(f"[SecretsManager] Invalid integer value for '{key}': '{val}'. Falling back to default {default}.")
            return default

    def get_list(self, key: str, default: List[str] = None, separator: str = ",") -> List[str]:
        """Safely retrieve comma-separated list of values (e.g., ALLOWED_ORIGINS)."""
        val = self.get(key)
        if not val:
            return default if default is not None else []
        return [item.strip() for item in val.split(separator) if item.strip()]

    def mask(self, key: str) -> str:
        """Return a masked representation of a secret value for safe diagnostic logging."""
        val = self.get(key)
        if not val:
            return "<NOT_SET>"
        if len(val) <= 8:
            return "****"
        return f"{val[:4]}...{val[-4:]}"

    def _validate_critical_secrets(self):
        """Run initial boot checks across known sensitive keys."""
        critical_keys = ["JWT_SECRET", "SUPABASE_KEY", "GEMINI_API_KEY"]
        for k in critical_keys:
            val = self.get(k)
            if not val or "YOUR_" in val:
                if self.env == "production":
                    logger.critical(f"[SecretsManager] Production check failed for {k}.")
                else:
                    logger.info(f"[SecretsManager] Dev mode check: {k} = {self.mask(k)}")


# Singleton export
secrets = SecretsManager()
