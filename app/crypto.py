"""Encryption at rest for stored secrets (Fernet: AES-128-CBC + HMAC-SHA256)."""
from cryptography.fernet import Fernet
from flask import current_app


def _fernet() -> Fernet:
    return Fernet(current_app.config["ENCRYPTION_KEY"].encode())


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    return _fernet().decrypt(token.encode()).decode()
