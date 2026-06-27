# -----------------------------------------------------------------------
# OpenXenManager-XCPNG
#
# Password utility module with optional master-password-based XTEA
# encryption and a simple fallback obfuscation when no master password
# is configured.
# -----------------------------------------------------------------------

import binascii


def _xor_obfuscate(plaintext: str, key: str = "openxenmanager-xcpng") -> str:
    """
    Simple XOR-based obfuscation (NOT cryptographically secure).

    Used only as a fallback when the user has not enabled a master password.
    The password is still stored in the config file rather than plaintext
    memory, but this should NOT be relied upon for sensitive data protection.
    """
    key_bytes = key.encode("utf-8")
    plain_bytes = plaintext.encode("utf-8")
    xored = bytes(p ^ key_bytes[i % len(key_bytes)] for i, p in enumerate(plain_bytes))
    return binascii.hexlify(xored).decode("ascii")


def _xor_deobfuscate(obfuscated: str, key: str = "openxenmanager-xcpng") -> str:
    """Reverse of ``_xor_obfuscate``."""
    key_bytes = key.encode("utf-8")
    xored = binascii.unhexlify(obfuscated.encode("ascii"))
    plain_bytes = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(xored))
    return plain_bytes.decode("utf-8")


def encrypt_password(
    password: str, use_master_password: bool, master_password: str, iv: tuple
) -> str:
    """
    Encrypt or obfuscate a password.

    * If ``use_master_password`` is True and ``master_password`` is set,
      the password is encrypted with XTEA and hex-encoded.
    * Otherwise a simple XOR obfuscation is applied (stored as hex string).

    Returns an empty string when the input password is empty.
    """
    if not password:
        return ""

    if use_master_password and master_password:
        from . import xtea  # noqa: local import to avoid circular deps

        # Pad or truncate key to 16 bytes for XTEA
        key = "X" * (16 - len(master_password)) + master_password
        encrypted = xtea.crypt(key, password.encode("latin-1"), iv)
        if isinstance(encrypted, bytes):
            return binascii.hexlify(encrypted).decode("ascii")
        return str(encrypted)

    # Fallback: XOR obfuscation
    return _xor_obfuscate(password)


def decrypt_password(
    stored: str, use_master_password: bool, master_password: str, iv: tuple
) -> str:
    """
    Decrypt or deobfuscate a previously stored password.

    Returns an empty string when the input is empty.
    Raises ``ValueError`` if decryption fails (e.g. wrong master password).
    """
    if not stored:
        return ""

    if use_master_password and master_password:
        from . import xtea  # noqa: local import to avoid circular deps

        key = "X" * (16 - len(master_password)) + master_password
        try:
            encrypted_bytes = binascii.unhexlify(stored.encode("ascii"))
            decrypted = xtea.crypt(key, encrypted_bytes, iv)
            if isinstance(decrypted, bytes):
                return decrypted.decode("latin-1")
            return str(decrypted)
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    # Fallback: XOR deobfuscation
    return _xor_deobfuscate(stored)


def is_obfuscated_password(value: str) -> bool:
    """Heuristic check: looks like our obfuscated hex string."""
    if len(value) < 4 or len(value) % 2 != 0:
        return False
    try:
        binascii.unhexlify(value.encode("ascii"))
        return True
    except Exception:
        return False
