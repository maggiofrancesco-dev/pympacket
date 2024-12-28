from pydantic import BaseModel
from Crypto.Hash import MD4
from Crypto.Cipher import ARC4
from binascii import hexlify, unhexlify
from impacket.krb5.asn1 import AS_REP
from pyasn1.codec.der import decoder

class Target(BaseModel):
    username: str
    domain: str
    hash: str


def compute_rc4_key(password):
    """
    Compute the RC4-HMAC key from the given password.
    """
    password_utf16 = password.encode("utf-16le")
    md4 = MD4.new()
    md4.update(password_utf16)
    return md4.digest()


def extract_encrypted_data(existing_hash):
    """
    Extract the encrypted data from an existing $krb5asrep$23$ hash.

    Args:
        existing_hash (str): An existing $krb5asrep$23$ hash.

    Returns:
        bytes: The encrypted data as bytes.
    """
    try:
        # Split the hash to extract components
        parts = existing_hash.split("$")
        if len(parts) != 5 or parts[1] != "krb5asrep" or parts[2] != "23":
            raise ValueError("Invalid $krb5asrep$23$ hash format.")
        encrypted_data_hex = parts[4]
        return unhexlify(encrypted_data_hex)
    except Exception as e:
        raise ValueError(f"Error extracting encrypted data: {e}")


def build_krb5asrep_hash(password, target):
    """
    Build a complete $krb5asrep$23$ hash using the given username, password, and domain.

    Args:
        username (str): Kerberos username.
        password (str): User's password.
        domain (str): Kerberos domain.

    Returns:
        str: The complete $krb5asrep$23$ hash.
    """
    # Compute RC4-HMAC key
    rc4_key = compute_rc4_key(password)

    # Simulate encrypted data
    encrypted_data = extract_encrypted_data(target.hash)
    encrypted_data_hex = hexlify(encrypted_data).decode()

    cipher = ARC4.new(rc4_key)
    decrypted_data = cipher.decrypt(encrypted_data)

    print(decrypted_data[:2])

    # Simulate checksum (first 8 bytes of RC4 key)
    checksum = hexlify(rc4_key[:8]).decode()

    # Build the hash
    krb5asrep_hash = f"$krb5asrep$23${target.username}@{target.domain}:{checksum}${encrypted_data_hex}"
    return krb5asrep_hash