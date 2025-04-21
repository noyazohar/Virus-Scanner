import socket
import time
import os
from Errors import ConnectionError
from encryption_utils import (
    encrypt_message, decrypt_message, encrypt_binary_data, decrypt_binary_data,
    perform_dh_key_exchange, calculate_data_hash
)


class Client:
    """
    A secure client for sending encrypted files to a server.

    This client uses Diffie-Hellman key exchange to establish a secure connection,
    then encrypts and sends files with validation checks to ensure data integrity.
    """

    def __init__(self, server_ip="127.0.0.1", server_port=5556, max_retries=3, retry_delay=2):
        """
        Initialize a new Client instance.

        Args:
            server_ip (str): The IP address of the server to connect to.
            server_port (int): The port number of the server.
            max_retries (int): Maximum number of connection attempts.
            retry_delay (int): Time in seconds to wait between retry attempts.
        """
        self.server_ip = server_ip
        self.server_port = server_port
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.shift_key = 7  # Default shift key, will be overridden by DH exchange

    def send_files_with_content(self, file_paths):
        """
        Send multiple files to the server with encryption and validation.

        This method:
        1. Establishes a connection with the server
        2. Performs Diffie-Hellman key exchange for secure encryption
        3. Sends each file in chunks with validation hashes
        4. Waits for server confirmation for each chunk
        5. Returns the server's analysis results

        Args:
            file_paths (list): List of paths to the files to be sent.

        Returns:
            dict: Server response with analysis results or error information.
        """
        attempt = 0
        while attempt < self.max_retries:
            try:
                # Verify that the provided file paths exist
                valid_file_paths = [file_path for file_path in file_paths if os.path.exists(file_path)]
                if not valid_file_paths:
                    return {"error": "No valid files found to send"}

                # Create and configure the socket
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client.settimeout(30)
                client.connect((self.server_ip, self.server_port))
                local_ip, local_port = client.getsockname()
                print(f"📡 Client local IP: {local_ip}, Source Port: {local_port}")

                # Perform Diffie-Hellman key exchange
                print("🔐 Performing Diffie-Hellman key exchange...")
                self.shift_key = perform_dh_key_exchange(client, is_server=False)
                print(f"🔑 Negotiated encryption shift value: {self.shift_key}")

                # Send the number of files that will be transmitted
                num_files_data = encrypt_message({"num_files": len(valid_file_paths)}, self.shift_key)
                client.sendall(num_files_data.encode())
                time.sleep(0.5)

                # Process each file
                for file_path in valid_file_paths:
                    file_name = os.path.basename(file_path)
                    file_size = os.path.getsize(file_path)

                    # Send encrypted file metadata
                    metadata = encrypt_message({"file_name": file_name, "file_size": file_size}, self.shift_key)
                    client.sendall(metadata.encode())
                    time.sleep(0.2)

                    # Read and send the file in chunks
                    with open(file_path, "rb") as f:
                        chunk_counter = 0
                        while chunk := f.read(4096):
                            chunk_counter += 1

                            # Encrypt chunk and generate validation hash
                            encrypted_chunk, original_hash = encrypt_binary_data(chunk, self.shift_key)

                            # Send metadata about the chunk (size, hash, sequence number)
                            chunk_metadata = {
                                "chunk_size": len(encrypted_chunk),
                                "chunk_hash": original_hash,
                                "chunk_num": chunk_counter
                            }
                            chunk_metadata_enc = encrypt_message(chunk_metadata, self.shift_key)
                            client.sendall(chunk_metadata_enc.encode())
                            time.sleep(0.1)

                            # Send the encrypted chunk itself
                            client.sendall(encrypted_chunk)

                            # Wait for server validation of the chunk
                            confirmation_data = client.recv(4096)
                            confirmation = decrypt_message(confirmation_data.decode(), self.shift_key)

                            # Handle validation failure
                            if not confirmation.get("valid", False):
                                print(f"Warning: Server reported chunk {chunk_counter} validation failed")
                                # Resend the chunk again (optional - could implement retry logic here)

                    # Mark the end of the file transmission
                    eof_marker = encrypt_message({
                        "eof": True,
                        "file_name": file_name,
                        "total_chunks": chunk_counter
                    }, self.shift_key)
                    client.sendall(eof_marker.encode())
                    time.sleep(0.2)

                # Receive and decrypt server response
                response_data = b""
                while True:
                    try:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        response_data += chunk

                        # Try to decrypt and parse the response
                        response = decrypt_message(response_data.decode(), self.shift_key)
                        # If we can parse it as a dictionary, we have the complete response
                        if isinstance(response, dict):
                            break
                    except Exception:
                        continue

                client.close()

                # Ensure all responses have the expected format
                for file_name, values in response.items():
                    if len(values) < 5:
                        response[file_name] = [0, 0, 0, 0, "Error in analysis"]

                return response

            except (socket.error, socket.timeout) as e:
                # Handle connection errors with retry logic
                attempt += 1
                if attempt >= self.max_retries:
                    return {"error": f"Could not connect to server after {self.max_retries} attempts. Error: {e}"}
                else:
                    time.sleep(self.retry_delay)

        return {"error": "Could not connect to server."}