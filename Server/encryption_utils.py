import json
import hashlib
import random
import socket
import base64
import os

# Diffie-Hellman Key Exchange constants
# Large prime number
DH_PRIME = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
# Base
DH_BASE = 2


def generate_dh_private_key(port_value):
    """
    Generate a Diffie-Hellman private key using port as seed.

    This function creates a reproducible private key by using the port number
    as a seed for the random number generator, ensuring consistent key generation
    across different executions with the same port.

    Args:
        port_value (int): Port number to use as seed

    Returns:
        int: A private key for Diffie-Hellman
    """
    # Seed random with the port value for reproducibility
    random.seed(port_value)
    # Generate a private key (a large random number)
    private_key = random.randint(2, DH_PRIME - 2)
    return private_key


def calculate_dh_public_key(private_key):
    """
    Calculate a Diffie-Hellman public key.

    Computes the public key using the formula: public_key = (base^private_key) mod prime
    The pow() function efficiently implements modular exponentiation.

    Args:
        private_key (int): Private key

    Returns:
        int: Public key for Diffie-Hellman exchange
    """
    return pow(DH_BASE, private_key, DH_PRIME)


def calculate_dh_shared_secret(other_public_key, my_private_key):
    """
    Calculate the shared secret using the other party's public key and our private key.

    This is the core of the Diffie-Hellman key exchange - both parties will arrive at
    the same shared secret value without ever transmitting this value directly.

    Args:
        other_public_key (int): Other party's public key
        my_private_key (int): Our private key

    Returns:
        int: Shared secret
    """
    return pow(other_public_key, my_private_key, DH_PRIME)


def calculate_data_hash(data):
    """
    Calculate SHA-256 hash of binary data.

    This function creates a cryptographic hash of binary data which can be used
    to verify data integrity - ensuring the data hasn't been modified during transfer.

    Args:
        data (bytes): Binary data to hash

    Returns:
        str: SHA-256 hash of the data as a hexadecimal string
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data)
    return sha256_hash.hexdigest()


def derive_encryption_shift(shared_secret):
    """
    Derive a simple Caesar shift from the Diffie-Hellman shared secret.

    This function converts the shared secret into a shift value (1-255) that can be
    used for basic Caesar cipher encryption. The process involves hashing the secret
    and using a portion of the hash to create the shift value.

    Args:
        shared_secret (int): Diffie-Hellman shared secret

    Returns:
        int: A shift value between 1 and 255
    """
    # Convert shared secret to bytes
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder='big')

    # Create a SHA-256 hash of the secret
    sha256 = hashlib.sha256()
    sha256.update(secret_bytes)
    hash_bytes = sha256.digest()

    # Use the sum of the first 4 bytes modulo 255 as the shift value (make sure it's not 0)
    shift = (sum(hash_bytes[:4]) % 255) + 1

    return shift


def caesar_encrypt(data, shift):
    """
    Encrypt data using a simple byte-by-byte Caesar cipher.

    This implementation of Caesar cipher shifts each byte value by the specified amount,
    wrapping around if necessary (using modulo 256 to stay within byte range 0-255).

    Args:
        data (bytes): Data to encrypt
        shift (int): Shift value for encryption

    Returns:
        bytes: Encrypted data
    """
    encrypted = bytearray()
    for byte in data:
        encrypted.append((byte + shift) % 256)
    return bytes(encrypted)


def caesar_decrypt(data, shift):
    """
    Decrypt data encrypted with caesar_encrypt.

    This function performs the inverse operation of caesar_encrypt, shifting each byte
    value back by the specified amount to recover the original data.

    Args:
        data (bytes): Encrypted data
        shift (int): Shift value used for encryption

    Returns:
        bytes: Decrypted data
    """
    decrypted = bytearray()
    for byte in data:
        decrypted.append((byte - shift) % 256)
    return bytes(decrypted)


def encrypt_message(message, shift):
    """
    Encrypt a message (string or dict) using Caesar cipher.

    This function handles both string and dictionary inputs (converting dictionaries to JSON),
    encrypts them using the Caesar cipher, and then encodes the result as a Base64 string
    for safe transmission.

    Args:
        message: Message to encrypt (string or dict)
        shift (int): Shift value for encryption

    Returns:
        str: Base64-encoded encrypted message
    """
    if isinstance(message, dict):
        message = json.dumps(message)

    if isinstance(message, str):
        message = message.encode()

    encrypted_data = caesar_encrypt(message, shift)
    return base64.b64encode(encrypted_data).decode()


def decrypt_message(encrypted_message, shift):
    """
    Decrypt a message and convert to dict if possible.

    This function decrypts a Base64-encoded encrypted message and attempts to parse
    it as JSON. If successful, it returns a dictionary; otherwise, it returns the
    decrypted data as a string.

    Args:
        encrypted_message (str): Base64-encoded encrypted message
        shift (int): Shift value used for encryption

    Returns:
        Union[dict, str]: Decrypted message as dict or string
    """
    encrypted_data = base64.b64decode(encrypted_message)
    decrypted_data = caesar_decrypt(encrypted_data, shift)
    decrypted_str = decrypted_data.decode()

    try:
        # Try to parse as JSON
        return json.loads(decrypted_str)
    except json.JSONDecodeError:
        # Return as string if not valid JSON
        return decrypted_str


def encrypt_binary_data(data, shift):
    """
    Encrypt binary data using Caesar cipher.

    This function encrypts binary data and also calculates a hash of the original data,
    which can be used to verify integrity after decryption.

    Args:
        data (bytes): Binary data to encrypt
        shift (int): Shift value for encryption

    Returns:
        tuple: (encrypted_data, data_hash) - Encrypted binary data and original data hash
    """
    # Calculate hash of original data for validation
    data_hash = calculate_data_hash(data)

    # Encrypt the data
    encrypted_data = caesar_encrypt(data, shift)

    return encrypted_data, data_hash


def decrypt_binary_data(encrypted_data, expected_hash, shift):
    """
    Decrypt binary data encrypted with encrypt_binary_data and validate integrity.

    This function decrypts data and verifies its integrity by comparing the hash of
    the decrypted data against the expected hash value provided.

    Args:
        encrypted_data (bytes): Encrypted binary data
        expected_hash (str): Expected hash of the decrypted data
        shift (int): Shift value used for encryption

    Returns:
        tuple: (decrypted_data, is_valid) - Decrypted data and validation result
    """
    # Decrypt the data
    decrypted_data = caesar_decrypt(encrypted_data, shift)

    # Calculate hash of decrypted data
    actual_hash = calculate_data_hash(decrypted_data)

    # Validate integrity
    is_valid = actual_hash == expected_hash

    return decrypted_data, is_valid


def derive_ports_from_socket(sock):
    """
    Extract the source and destination ports from a socket.

    This function retrieves the local port (source) and remote port (destination)
    from a connected socket. If the socket is not connected, the destination port
    is set to 0.

    Args:
        sock (socket.socket): The socket to extract ports from

    Returns:
        tuple: (src_port, dst_port)
    """
    src_port = sock.getsockname()[1]
    try:
        dst_port = sock.getpeername()[1]
    except socket.error:
        # If not connected yet
        dst_port = 0

    return src_port, dst_port


def perform_dh_key_exchange(sock, is_server=False):
    """
    Perform Diffie-Hellman key exchange over the given socket.

    This function handles the full Diffie-Hellman key exchange process, including
    generating keys, exchanging public keys with the other party, and deriving
    a shared encryption shift value. The protocol differs slightly depending on
    whether this is running on the server or client side.

    Args:
        sock (socket.socket): The socket to perform key exchange over
        is_server (bool): Whether this is the server side

    Returns:
        int: The derived encryption shift value
    """
    # Get ports
    src_port, dst_port = derive_ports_from_socket(sock)

    # Initial shift for handshake only
    initial_shift = 7

    # Generate private key based on source port
    my_private_key = generate_dh_private_key(src_port)

    # Calculate public key
    my_public_key = calculate_dh_public_key(my_private_key)

    # Exchange public keys
    if is_server:
        # Server receives client's public key first
        data = sock.recv(4096)
        client_public_key_data = decrypt_message(data.decode(), initial_shift)
        client_public_key = int(client_public_key_data["public_key"])

        # Server sends its public key
        server_data = encrypt_message({"public_key": str(my_public_key)}, initial_shift)
        sock.sendall(server_data.encode())

        # Calculate shared secret
        shared_secret = calculate_dh_shared_secret(client_public_key, my_private_key)
    else:
        # Client sends its public key first
        client_data = encrypt_message({"public_key": str(my_public_key)}, initial_shift)
        sock.sendall(client_data.encode())

        # Client receives server's public key
        data = sock.recv(4096)
        server_public_key_data = decrypt_message(data.decode(), initial_shift)
        server_public_key = int(server_public_key_data["public_key"])

        # Calculate shared secret
        shared_secret = calculate_dh_shared_secret(server_public_key, my_private_key)

    # Derive encryption key from shared secret
    encryption_shift = derive_encryption_shift(shared_secret)

    return encryption_shift