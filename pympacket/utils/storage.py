import os
import json
from pydantic import BaseModel
from pympacket.models.common import User, Computer, Domain

# Class to save on disk
class Storage(BaseModel):
    users: list[User] = []
    computers: list[Computer] = []
    domain_info: Domain | None = None

STORAGE_FILE = "storage"
SECRET_KEY = "20LqnLTCr9JWeWYRjH5LdnVO+5C3EN9b6Je43PpEfXSXx6wkd03tJKtWNebjOifS"  # Simple static key for XOR

def xor_encrypt_decrypt(data: bytes, key: str) -> bytes:
    """Encrypt or decrypt data using a basic XOR cipher with byte output."""
    key = (key * (len(data) // len(key) + 1))[:len(data)].encode()  # Repeat the key
    return bytes(c ^ k for c, k in zip(data, key))

def encrypt_data(data: Storage) -> bytes:
    """Encrypt data using XOR and output as raw bytes."""
    json_data = data.model_dump_json().encode()  # Convert JSON to bytes
    return xor_encrypt_decrypt(json_data, SECRET_KEY)

def decrypt_data(data: bytes) -> Storage:
    """Decrypt raw byte data using XOR."""
    decrypted_bytes = xor_encrypt_decrypt(data, SECRET_KEY)
    if not decrypted_bytes:
        return Storage()
    return Storage(**json.loads(decrypted_bytes.decode()))  # Convert back to dict

def save_storage(data: Storage):
    """Save encrypted data to a file."""
    encrypted_data = encrypt_data(data)
    with open(STORAGE_FILE, "wb") as storage_file:
        storage_file.write(encrypted_data)

def load_storage() -> Storage:
    """Load and decrypt data from the storage file."""
    try:
        if not os.path.exists(STORAGE_FILE):
            return Storage()  # Return empty storage if the file doesn't exist
        with open(STORAGE_FILE, "rb") as storage_file:
            encrypted_data = storage_file.read()
        return decrypt_data(encrypted_data)
    except:
        storage = Storage()
        save_storage(storage)
        return storage