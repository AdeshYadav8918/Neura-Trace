"""
Crypto Vault - AES-256-GCM encryption for sensitive data at rest.
Key is derived from VAULT_MASTER_KEY_B64 env variable if set,
otherwise falls back to plaintext mode so existing files are never corrupted.
"""

import os
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


class SecureVault:
    """AES-256-GCM encryption vault. Gracefully degrades to plaintext if key not set."""

    def __init__(self):
        self.aesgcm = None
        key_b64 = os.environ.get("VAULT_MASTER_KEY_B64")

        if CRYPTO_AVAILABLE and key_b64:
            try:
                key = base64.b64decode(key_b64)
                self.aesgcm = AESGCM(key)
                logger.info("SecureVault: AES-256-GCM encryption active.")
            except Exception as e:
                logger.warning(f"SecureVault: invalid key, falling back to plaintext. {e}")
        else:
            logger.info("SecureVault: VAULT_MASTER_KEY_B64 not set — running in plaintext mode.")

    @property
    def encryption_enabled(self) -> bool:
        return self.aesgcm is not None

    def encrypt_and_save(self, data: bytes, filepath: str) -> bool:
        """Save data. Encrypts if key is configured, otherwise saves plaintext."""
        if self.aesgcm:
            nonce = os.urandom(12)
            ciphertext = self.aesgcm.encrypt(nonce, data, associated_data=b"neuratrace_vault")
            with open(filepath, 'wb') as f:
                f.write(b"ENC:" + nonce + ciphertext)
        else:
            # Plaintext fallback — preserves full functionality without a key
            with open(filepath, 'wb') as f:
                f.write(data)
        return True

    def read_and_decrypt(self, filepath: str) -> Optional[bytes]:
        """Read file. Decrypts if encrypted header is found, else returns raw bytes."""
        if not os.path.exists(filepath):
            return None

        with open(filepath, 'rb') as f:
            content = f.read()

        # Check for encryption marker
        if content.startswith(b"ENC:") and self.aesgcm:
            try:
                payload = content[4:]
                nonce = payload[:12]
                ciphertext = payload[12:]
                return self.aesgcm.decrypt(nonce, ciphertext, associated_data=b"neuratrace_vault")
            except Exception as e:
                logger.error(f"Decryption failed for {filepath}: {e}")
                return None

        # Return as-is (plaintext JSON or unencrypted file)
        return content

    def secure_delete(self, filepath: str):
        """Overwrite file before deletion (basic secure erase)."""
        if os.path.exists(filepath):
            try:
                length = os.path.getsize(filepath)
                with open(filepath, "r+b") as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(length))
            except Exception:
                pass
            os.remove(filepath)


# Singleton
vault = SecureVault()
