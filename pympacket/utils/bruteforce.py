from Crypto.Cipher import ARC4
from Crypto.Hash import MD4, HMAC, MD5
from binascii import unhexlify
from pympacket.models.common import Hash

def utf16le_encode(data):
    """Encodes a string to UTF-16LE."""
    return data.encode('utf-16le')

def md4_hash(data):
    """Computes the MD4 hash of the input data."""
    md4 = MD4.new()
    md4.update(data)
    return md4.digest()

def hmac_md5(key, data):
    """Computes HMAC-MD5 of the data using the given key."""
    hmac = HMAC.new(key, digestmod=MD5)
    hmac.update(data)
    return hmac.digest()

def rc4_decrypt(key, data):
    """Decrypts data using RC4 with the given key."""
    cipher = ARC4.new(key)
    return cipher.decrypt(data)

def parse_asrep_hash(asrep_hash):
    """Parses the AS-REP hash and extracts components."""
    parts = asrep_hash.split('$')
    if len(parts) != 5 or parts[1] != 'krb5asrep' or parts[2] != '23':
        raise ValueError("Invalid AS-REP hash format.")

    checksum = unhexlify(parts[3].split(':')[1])
    encrypted_data = unhexlify(parts[4])
    
    return {
        'checksum': checksum,
        'encrypted_data': encrypted_data
    }

def parse_tgs_hash(tgs_hash):
    """Parses the TGS hash and extracts components."""
    parts = tgs_hash.split('$')
    if len(parts) != 8 or parts[1] != 'krb5tgs' or parts[2] != '23':
        raise ValueError("Invalid TGS hash format.")

    checksum = unhexlify(parts[6])
    encrypted_data = unhexlify(parts[7])

    return {
        'checksum': checksum,
        'encrypted_data': encrypted_data
    }


def verify_hash(password, hash, hash_type):
    """Verifies if the provided password matches the given AS-REP/TGS hash."""
    if hash_type == 'asrep':
        data = b'\x08\x00\x00\x00'  # Constant 4-byte input for HMAC-MD5
        parsed_hash = parse_asrep_hash(hash)
    else:
        data = b'\x02\x00\x00\x00'  # Constant 4-byte input for HMAC-MD5
        parsed_hash = parse_tgs_hash(hash)

    # Step 1: Convert password to UTF-16LE and compute the RC4-HMAC key
    password_utf16 = utf16le_encode(password)
    rc4_key = md4_hash(password_utf16)

    # Step 2: Compute K1 using HMAC-MD5 with the RC4 key and the constant data
    K1 = hmac_md5(rc4_key, data)

    # Step 3: Compute K3 using HMAC-MD5 with K1 and the checksum (edata1)
    K3 = hmac_md5(K1, parsed_hash['checksum'])

    # Step 4: Decrypt the first 32 bytes of the encrypted data (edata2) using RC4 with K3
    encrypted_data = parsed_hash['encrypted_data']

    # Step 5: Decrypt the remaining data
    decrypted_data = rc4_decrypt(K3, encrypted_data)

    # Step 6: Compute the checksum of the decrypted data using HMAC-MD5 with K1
    computed_checksum = hmac_md5(K1, decrypted_data)

    # Step 7: Compare the computed checksum with the original checksum (edata1)
    return computed_checksum[:16] == parsed_hash['checksum']

def bruteforce(wordlist, hash: Hash):
    with open(wordlist, 'r') as wordlist:
        for line in wordlist:
            password = line.strip()
            if verify_hash(password, hash.value, hash.type):
                return password
        return None