"""Configuration loaded from environment variables (.env on the server).

Secrets are never hard-coded. The app refuses to start if any required
secret is missing or too short, so a half-configured install can't run.
"""
import os


class ConfigError(RuntimeError):
    pass


def _required(name: str, min_len: int) -> str:
    value = os.environ.get(name, "")
    if len(value) < min_len:
        raise ConfigError(
            f"{name} is missing or shorter than {min_len} characters. "
            "Run scripts/generate_env.py to create a .env file."
        )
    return value


def _flag(name: str, default: str) -> bool:
    return os.environ.get(name, default).strip() == "1"


def load_config() -> dict:
    return {
        # Signs the pre-login CSRF cookie.
        "SECRET_KEY": _required("SECRET_KEY", 32),
        # Keys the audit-log hash chain (tamper evidence).
        "AUDIT_HMAC_KEY": _required("AUDIT_HMAC_KEY", 32),
        # Fernet key: encrypts the TOTP secret (and later the Google token / Claude key).
        "ENCRYPTION_KEY": _required("ENCRYPTION_KEY", 44),
        # One-time token needed to create the first account at /setup.
        "SETUP_TOKEN": _required("SETUP_TOKEN", 24),
        "DATA_DIR": os.environ.get("DATA_DIR", "/data"),
        # Must stay 1 in production (Cloudflare serves the site over HTTPS).
        "COOKIE_SECURE": _flag("COOKIE_SECURE", "1"),
        # Trust Cloudflare's CF-Connecting-IP header for the real client IP.
        # Safe only because the app is reachable solely through cloudflared.
        "TRUST_PROXY_HEADERS": _flag("TRUST_PROXY_HEADERS", "1"),
        "APP_TIMEZONE": os.environ.get("APP_TIMEZONE", "America/New_York"),
        "BUILD_DATE": os.environ.get("BUILD_DATE", "unknown"),
        "SECURITY_DIR": os.environ.get("SECURITY_DIR", "/app/security"),
    }
