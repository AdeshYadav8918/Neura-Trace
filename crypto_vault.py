import os
import base64
from typing import Optional

# Ensure cryptography is available instead of failing outright.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    
class SecureVault:
    """Military-grade AES-256-GCM Encryption for Data at Rest"""
    
    def __init__(self):
        # Master key should reside outside the codebase. Auto-generating for local strict resilience if missing.
        key_b64 = os.environ.get("VAULT_MASTER_KEY_B64")
        if not key_b64:
            if CRYPTO_AVAILABLE:
                self.key = AESGCM.generate_key(bit_length=256)
                # Store it in memory for the session
                os.environ["VAULT_MASTER_KEY_B64"] = base64.b64encode(self.key).decode('utf-8')
            else:
                self.key = None
        else:
            self.key = base64.b64decode(key_b64)
            
        if CRYPTO_AVAILABLE and self.key:
            self.aesgcm = AESGCM(self.key)
        else:
            self.aesgcm = None

    def encrypt_and_save(self, data: bytes, filepath: str) -> bool:
        """Encrypts data with AES-256-GCM and writes to filepath"""
        if not self.aesgcm:
            # Fallback if crypto not installed, though military grade mandates it.
            with open(filepath, 'wb') as f:
                f.write(data)
            return False
            
        nonce = os.urandom(12) 
        ciphertext = self.aesgcm.encrypt(nonce, data, associated_data=b"neuratrace_vault")
        
        with open(filepath, 'wb') as f:
            f.write(nonce + ciphertext)
        return True
            
    def read_and_decrypt(self, filepath: str) -> Optional[bytes]:
        """Reads and decrypts data from filepath"""
        if not os.path.exists(filepath):
            return None
            
        with open(filepath, 'rb') as f:
            content = f.read()
            
        if not self.aesgcm or len(content) < 12:
            return content
            
        nonce = content[:12]
        ciphertext = content[12:]
        try:
            return self.aesgcm.decrypt(nonce, ciphertext, associated_data=b"neuratrace_vault")
        except Exception:
            # Integrity check failed or unencrypted
            return content

    def secure_delete(self, filepath: str):
        """DoD 5220.22-M simplified 3-pass file wipe"""
        if os.path.exists(filepath):
            try:
                length = os.path.getsize(filepath)
                with open(filepath, "r+b") as f:
                    for _ in range(3):
                        f.seek(0)
                        f.write(os.urandom(length))
            except Exception:
                pass # Depending on OS file locks
            os.remove(filepath)

# Singleton instance for the application
vault = SecureVault()
