import socket
import threading
import os
import sys
import json
import time
import hashlib
import base64

# Add project path to system path to allow imports
path1 = r"C:\code\python\school\VirusProject\Server\menoim"
sys.path.append(path1)
from db_operations import get_file_info, insert_file
from main import new_check_of_file
from encryption_utils import (
    encrypt_message, decrypt_message, encrypt_binary_data, decrypt_binary_data,
    calculate_data_hash, perform_dh_key_exchange
)

# Configure upload folder for received files
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Default encryption shift (will be overridden by Diffie-Hellman key exchange)
SHIFT_KEY = 7


def calculate_file_hash(file_path):
    """
    Compute SHA-256 hash of a file.

    Args:
        file_path (str): Path to the file to be hashed

    Returns:
        str: Hexadecimal string representation of the SHA-256 hash
    """
    hash_sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def handle_client(client_socket, client_address):
    """
    Handle an individual client connection including file reception,
    decryption, analysis, and sending results back to client.

    Args:
        client_socket (socket): Socket object for communication with the client
        client_address (tuple): Client's address information (IP, port)
    """
    print(f"[+] Connection accepted from {client_address}")

    try:
        # Perform Diffie-Hellman key exchange for secure communication
        print(f"[+] Performing Diffie-Hellman key exchange with {client_address}")
        shift_key = perform_dh_key_exchange(client_socket, is_server=True)
        print(f"[+] Negotiated encryption shift value with {client_address}: {shift_key}")

        # Receive encrypted data with the negotiated key
        data = client_socket.recv(4096)
        if not data:
            return

        # Decrypt the data to get number of files being sent
        num_files_info = decrypt_message(data.decode(), shift_key)
        num_files = num_files_info.get("num_files", 0)
        print(f"[+] Client will send {num_files} files")

        # Dictionary to store analysis results for all files
        results = {}

        # Process each file from the client
        for _ in range(num_files):
            # Receive and decrypt file metadata
            metadata_data = client_socket.recv(4096)
            if not metadata_data:
                break

            metadata = decrypt_message(metadata_data.decode(), shift_key)
            file_name = metadata.get("file_name")
            file_size = metadata.get("file_size")
            file_path = os.path.join(UPLOAD_FOLDER, file_name)

            # Track validation statistics for file transfer integrity
            valid_chunks = 0
            invalid_chunks = 0
            total_expected_chunks = 0

            # Receive and decrypt file content in chunks with validation
            with open(file_path, "wb") as f:
                while True:
                    # Receive chunk metadata (size and hash for validation)
                    chunk_metadata_data = client_socket.recv(4096)
                    if not chunk_metadata_data:
                        break

                    try:
                        # Decrypt the chunk metadata
                        chunk_metadata = decrypt_message(chunk_metadata_data.decode(), shift_key)

                        # Check if this is an end-of-file marker
                        if chunk_metadata.get("eof"):
                            total_expected_chunks = chunk_metadata.get("total_chunks", 0)
                            print(f"[+] End of file reached for {file_name}. Expected chunks: {total_expected_chunks}")
                            break

                        # Extract chunk information
                        chunk_size = chunk_metadata.get("chunk_size")
                        original_hash = chunk_metadata.get("chunk_hash")
                        chunk_num = chunk_metadata.get("chunk_num", 0)

                        # Receive the encrypted chunk in parts if needed
                        encrypted_chunk = b""
                        bytes_received = 0
                        while bytes_received < chunk_size:
                            part = client_socket.recv(min(4096, chunk_size - bytes_received))
                            if not part:
                                break
                            encrypted_chunk += part
                            bytes_received += len(part)

                        # Decrypt the chunk and validate integrity using hash
                        decrypted_chunk, is_valid = decrypt_binary_data(encrypted_chunk, original_hash, shift_key)

                        # Send validation confirmation back to client
                        confirmation = encrypt_message({
                            "valid": is_valid,
                            "chunk_num": chunk_num
                        }, shift_key)
                        client_socket.sendall(confirmation.encode())

                        # If valid, write to file
                        if is_valid:
                            f.write(decrypted_chunk)
                            valid_chunks += 1
                        else:
                            print(f"[!] Invalid chunk {chunk_num} detected for file {file_name}")
                            invalid_chunks += 1

                    except Exception as e:
                        # Check if this might be an end-of-file marker
                        try:
                            eof_info = decrypt_message(chunk_metadata_data.decode(), shift_key)
                            if eof_info.get("eof"):
                                total_expected_chunks = eof_info.get("total_chunks", 0)
                                break
                        except:
                            pass
                        print(f"[!] Error receiving file chunk: {e}")

                        # Send error confirmation to client
                        error_confirmation = encrypt_message({
                            "valid": False,
                            "error": str(e)
                        }, shift_key)
                        client_socket.sendall(error_confirmation.encode())
                        break

            # Log file transfer validation results
            print(
                f"[+] File {file_name} transfer completed: {valid_chunks} valid chunks, {invalid_chunks} invalid chunks")
            if total_expected_chunks > 0:
                if valid_chunks == total_expected_chunks:
                    print(f"[+] Full file integrity confirmed for {file_name}")
                else:
                    print(
                        f"[!] File integrity check failed for {file_name}: Expected {total_expected_chunks}, got {valid_chunks} valid chunks")

            # Calculate file hash for database lookup
            file_hash = calculate_file_hash(file_path)

            # Check if file has been analyzed before (cached in database)
            db_result = get_file_info(file_hash)

            # Process analysis results - either from database or new analysis
            if db_result and any(float(score) > 0 for score in db_result[:-1] if score is not None):
                # Extract results from database
                malicious_score = float(db_result[0]) if db_result[0] is not None else 0.0
                magic_score = float(db_result[1]) if db_result[1] is not None else 0.0
                maleware_bazzar_score = float(db_result[2]) if db_result[2] is not None else 0.0
                data_analysis_score = float(db_result[3]) if db_result[3] is not None else 0.0
                detection_mechanisms = db_result[4] if db_result[4] is not None else "No detection mechanisms found"
            else:
                # Perform new analysis on the file
                try:
                    result = new_check_of_file(file_path)
                    print("Result from new_check_of_file:", result)

                    # Ensure result has expected format
                    if result and len(result) >= 5:
                        malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms = result
                    else:
                        print(f"[!] Unexpected result format for {file_name}: {result}")
                        malicious_score = magic_score = maleware_bazzar_score = data_analysis_score = 0.0
                        detection_mechanisms = "Error in analysis"
                except Exception as e:
                    print(f"[!] Error in new_check_of_file for {file_name}: {e}")
                    malicious_score = magic_score = maleware_bazzar_score = data_analysis_score = 0.0
                    detection_mechanisms = f"Error: {str(e)}"

            # Add validation info to results
            detection_mechanisms_with_validation = detection_mechanisms

            # Store rounded results for this file
            results[file_name] = [
                round(float(malicious_score), 2),
                round(float(magic_score), 2),
                round(float(maleware_bazzar_score), 2),
                round(float(data_analysis_score), 2),
                detection_mechanisms_with_validation
            ]

        # Encrypt the combined results for all files and send back to client
        encrypted_response = encrypt_message(results, shift_key)
        client_socket.sendall(encrypted_response.encode())

    except Exception as e:
        print(f"[!] Error handling client {client_address}: {e}")
        # Use the default key for error response if DH exchange failed
        error_response = encrypt_message({"error": str(e)}, SHIFT_KEY)
        client_socket.sendall(error_response.encode())
    finally:
        client_socket.close()
        print(f"[-] Connection closed with {client_address}")


def start_server(host="0.0.0.0", port=5556):
    """
    Start the socket server to listen for client connections.

    Args:
        host (str): IP address to bind the server to (default: "0.0.0.0" - all interfaces)
        port (int): Port number to listen on (default: 5556)
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((host, port))
        server.listen(5)  # Allow up to 5 queued connections
        print(f"[*] Server listening on {host}:{port}")

        # Main server loop to accept connections
        while True:
            client_sock, address = server.accept()
            # Create a new thread to handle each client
            client_handler = threading.Thread(target=handle_client, args=(client_sock, address))
            client_handler.daemon = True
            client_handler.start()

    except Exception as e:
        print(f"[!] Error starting server: {e}")
    finally:
        server.close()


if __name__ == "__main__":
    start_server()
