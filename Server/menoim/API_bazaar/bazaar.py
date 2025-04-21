"""
Malbazaar Lookup Tool (bazar.py)
--------------------------------
A tool for querying malware samples on MalBazaar by hash or file path.
The tool supports scanning individual files or archives and their contents.

Features:
- Lookup file information using hash (MD5/SHA1/SHA256)
- File scanning and hash generation
- Archive extraction and scanning (supports ZIP, RAR, TAR, GZIP, BZ2, XZ)
- Recursive scanning of nested archives

Usage:
    python bazar.py --file <filepath>
    python bazar.py --hash <file_hash>
    python bazar.py --file <filepath> --scan-archive
"""

import argparse
import hashlib
import requests
import os
import logging
import tempfile
import zipfile
import tarfile
import gzip
import bz2
import lzma
import shutil
from pathlib import Path

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Dictionary of archive file signatures for identification
ARCHIVE_SIGNATURES = {
    b'PK\x03\x04': 'zip',
    b'\x1F\x8B\x08': 'gzip',
    b'BZh': 'bzip2',
    b'\xFD\x37\x7A\x58\x5A\x00': 'xz',
    b'Rar!\x1A\x07\x00': 'rar',
    b'Rar!\x1A\x07\x01\x00': 'rar5',
    b'\x75\x73\x74\x61\x72': 'tar'
}


def is_archive_file(file_path):
    """
    Check if a file is a recognized archive type based on its signature.

    Args:
        file_path (str): Path to the file to check

    Returns:
        tuple: (is_archive, archive_type) where:
            - is_archive (bool): True if the file is a recognized archive
            - archive_type (str or None): Type of archive, or None if not an archive
    """
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(16)  # Read enough bytes to check signatures

            # Check if file signature matches any known archive types
            for signature, archive_type in ARCHIVE_SIGNATURES.items():
                if magic_bytes.startswith(signature):
                    return True, archive_type

            # Special case for tar files which don't have a clear signature
            if tarfile.is_tarfile(file_path):
                return True, 'tar'

            return False, None
    except Exception as e:
        logging.error(f"Error checking archive signature: {e}")
        return False, None


def extract_archive(archive_path, temp_dir):
    """
    Extract an archive file to a temporary directory based on its type.

    Args:
        archive_path (str): Path to the archive file
        temp_dir (str): Path to the temporary directory for extraction

    Returns:
        bool: True if extraction was successful, False otherwise
    """
    is_archive, archive_type = is_archive_file(archive_path)

    if not is_archive:
        logging.error(f"File {archive_path} is not a recognized archive")
        return False

    try:
        if 'zip' in archive_type:
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
        elif 'rar' in archive_type:
            try:
                import rarfile
                with rarfile.RarFile(archive_path, 'r') as rar_ref:
                    rar_ref.extractall(temp_dir)
            except ImportError:
                logging.error("The rarfile library is required to extract RAR files. Install with: pip install rarfile")
                return False
        elif archive_type == 'tar':
            with tarfile.open(archive_path, 'r') as tar_ref:
                tar_ref.extractall(temp_dir)
        elif archive_type == 'gzip':
            # gzip typically contains a single file
            output_path = os.path.join(temp_dir, os.path.basename(archive_path)[:-3])
            with gzip.open(archive_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif archive_type == 'bzip2':
            output_path = os.path.join(temp_dir, os.path.basename(archive_path)[:-4])
            with bz2.open(archive_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        elif archive_type == 'xz':
            output_path = os.path.join(temp_dir, os.path.basename(archive_path)[:-3])
            with lzma.open(archive_path, 'rb') as f_in:
                with open(output_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
        return True
    except Exception as e:
        logging.error(f"Error extracting archive {archive_path}: {e}")
        return False


# Set up command line argument parsing
parser = argparse.ArgumentParser(description='Query sample information by Hash or File.')

parser.add_argument('--file', dest='file', type=str, help='Query File at filepath (e.g. /foo/bar/blah.exe)')
parser.add_argument('--hash', dest='hash', type=str, help='Query Hash (MD5/SHA1/SHA256)')
parser.add_argument('--scan-archive', dest='scan_archive', action='store_true', help='Scan archive and its contents')
args = parser.parse_args()


def md5hash(file):
    """
    Calculate MD5 hash for a file.

    Args:
        file (str): Path to the file

    Returns:
        str: MD5 hash value as a hexadecimal string
    """
    BSIZE = 65536  # Read file in 64KB chunks
    hnd = open(file, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    hnd.close()
    return hashmd5.hexdigest()


def sha1hash(file):
    """
    Calculate SHA-1 hash for a file.

    Args:
        file (str): Path to the file

    Returns:
        str: SHA-1 hash value as a hexadecimal string
    """
    BSIZE = 65536  # Read file in 64KB chunks
    hnd = open(file, 'rb')
    hashsha1 = hashlib.sha1()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha1.update(info)
    hnd.close()
    return hashsha1.hexdigest()


def sha256hash(file):
    """
    Calculate SHA-256 hash for a file.

    Args:
        file (str): Path to the file

    Returns:
        str: SHA-256 hash value as a hexadecimal string
    """
    BSIZE = 65536  # Read file in 64KB chunks
    hnd = open(file, 'rb')
    hashsha256 = hashlib.sha256()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha256.update(info)
    hnd.close()
    return hashsha256.hexdigest()


def malbazaarlookup(hash_or_file, is_file=True):
    """
    Query MalBazaar API for information about a file or hash.

    Args:
        hash_or_file (str): Path to file or hash value
        is_file (bool): Whether the input is a file path (True) or hash value (False)

    Returns:
        bool: True if the sample was found on MalBazaar, False otherwise
    """
    if is_file:
        hash_value = sha256hash(hash_or_file)
        print(f"\nSHA256 hash of file: {hash_value}")
    else:
        hash_value = hash_or_file

    # Prepare API request data
    data = {'query': 'get_info', 'hash': hash_value}
    url = "https://mb-api.abuse.ch/api/v1/"
    response = requests.post(url, data=data)

    # Check for valid response
    if response.status_code != 200:
        print(f'Error: API request failed with status code {response.status_code}')
        return False

    try:
        response_json = response.json()
    except Exception as e:
        print(f'Error parsing JSON response: {e}')
        return False

    # Check if hash was found
    if response_json.get("query_status") == 'hash_not_found':
        print('>>>>>>>>>>  The sample hash was not found on Malbazaar  <<<<<<<<<<')
        return False

    try:
        # Process and display MalBazaar information
        response_data = response_json.get("data", [{}])[0]
        vendor_intel = response_data.get("vendor_intel", {})

        # Display basic file information
        print('###############<<<  File Info  >>>###############')
        print('#################################################')
        file_name = response_data.get("file_name", "N/A")
        print('')
        print("Filename: " + file_name)
        print('')
        file_type_mime = response_data.get("file_type_mime", "N/A")
        file_type = response_data.get("file_type", "N/A")
        print("MIME File Type: " + file_type_mime)
        print("     File Type: " + file_type)
        print('')
        first_seen = response_data.get("first_seen", "N/A")
        last_seen = response_data.get("last_seen", "N/A")
        print("First Seen: " + str(first_seen))
        print(" Last Seen: " + str(last_seen))
        print('')
        malbazaar_signature = response_data.get('signature', "N/A")
        print('Signature: ' + str(malbazaar_signature))
        print('')
        tags = response_data.get("tags", [])
        print("Tags:", tags)
        print('')
        print('')

        # Display YARA rule information
        yara_rules = response_data.get('yara_rules', [])
        if yara_rules:
            print('###############<<<  YARA rule information  >>>###############')
            print('#############################################################')
            print('')
            for yar in range(0, len(yara_rules)):
                print("YARA Rule name: " + str(yara_rules[yar].get('rule_name', "N/A")))
                print("YARA Description: " + str(yara_rules[yar].get('description', "N/A")))
                print('')
                print('')

        # Display hash information
        print('###############<<<  File HASH information  >>>###############')
        print('#############################################################')
        print('')
        sha256_hash = response_data.get("sha256_hash", "N/A")
        sha1_hash = response_data.get("sha1_hash", "N/A")
        md5_hash = response_data.get("md5_hash", "N/A")
        print("   MD5 hash: " + md5_hash)
        print("  SHA1 hash: " + sha1_hash)
        print("SHA256 hash: " + sha256_hash)
        print('')
        imphash_hash = response_data.get("imphash", "N/A")
        ssdeep_hash = response_data.get("ssdeep", "N/A")
        print("    IMPHASH: " + str(imphash_hash))
        print('')
        print("     SSDEEP: " + ssdeep_hash)
        print('')
        print('')

        # Display intelligence information
        print('###############<<<  File Intelligence information  >>>###############')
        print('#####################################################################')
        print('')
        delivery_method = response_data.get("delivery_method", "N/A")
        print("Delivery method: " + str(delivery_method))
        print('')
        intelligence = response_data.get("intelligence", {}).get("clamav", "N/A")
        print('Intelligence: ' + str(intelligence))
        print('')
        print('')

        # Display vendor intelligence information
        # ReversingLabs
        ReversingLabs = vendor_intel.get("ReversingLabs", {})
        if ReversingLabs:
            ReversingLabs_verdict = ReversingLabs.get("status", "N/A")
            ReversingLabs_threatname = ReversingLabs.get("threat_name", "N/A")
            ReversingLabs_firstseen = ReversingLabs.get("first_seen", "N/A")
            print('###############<<<  REVERSINGLABS info  >>>###############')
            print('##########################################################')
            print('ReversingLabs verdict: ' + ReversingLabs_verdict)
            print('ReversingLabs threatname: ', ReversingLabs_threatname)
            print('ReversingLabs firstseen: ' + ReversingLabs_firstseen)
            print('')
            print('')
        else:
            print('No ReversingLabs data available.')

        # ANY.RUN information
        anyrun_info = vendor_intel.get("ANY.RUN", [])
        if anyrun_info:
            ANYRUN_verdict = anyrun_info[0].get("verdict", "N/A")
            ANYRUN_firstseen = anyrun_info[0].get("date", "N/A")
            ANYRUN_URL = anyrun_info[0].get("analysis_url", "N/A")
            print('###############<<<  ANY.RUN info  >>>###############')
            print('ANY.RUN verdict:', ANYRUN_verdict)
            print('ANY.RUN firstseen:', ANYRUN_firstseen)
            print('ANY.RUN Analysis URL:', ANYRUN_URL)
            print('')
            print('')

        # Hatching Triage information
        HatchingTriage_info = vendor_intel.get("Triage", {})
        if HatchingTriage_info:
            HatchingTriage_verdict = HatchingTriage_info.get("score", "N/A")
            HatchingTriage_malwarefamily = HatchingTriage_info.get("malware_family", "N/A")
            HatchingTriage_tags = HatchingTriage_info.get("tags", "N/A")
            HatchingTriage_URL = HatchingTriage_info.get("link", "N/A")
            print('###############<<<  HatchingTriage info  >>>###############')
            print('###########################################################')
            print('Hatching Triage verdict: ' + HatchingTriage_verdict)
            print('Hatching Triage Malware family: ' + HatchingTriage_malwarefamily)
            print('Hatching Triage tags: ' + str(HatchingTriage_tags))
            print('Hatching Triage Analysis URL: ' + HatchingTriage_URL)
            print('')
            print('')

        # UnpacME information
        unpac_me = vendor_intel.get("UnpacMe", [])
        if unpac_me:
            print('##################<<<  Unpac Me info  >>>##################')
            print('###########################################################')
            print('')
            for unp in range(0, len(unpac_me)):
                print("   MD5 hash: " + (unpac_me[unp].get('md5_hash', "N/A")))
                print("SHA256 hash: " + (unpac_me[unp].get('sha256_hash', "N/A")))
                print("Link: " + unpac_me[unp].get('link', "N/A"))
                print("Detections: " + str(unpac_me[unp].get('detections', "N/A")))
                print('')

        # Display MalBazaar page link
        print('###############<<<  AbuseCH Malware Bazaar info  >>>###############')
        print('###################################################################')
        print('')
        print('AbuseCH Malware Bazaar page:')
        print('https://bazaar.abuse.ch/sample/' + sha256_hash)
        print('')

        return True
    except Exception as e:
        print(f"Error processing data from server: {e}")
        return False


def scan_archive_files(archive_path):
    """
    Scan an archive file and all its contents by recursively extracting and checking each file.

    Args:
        archive_path (str): Path to the archive file to scan

    Returns:
        list: Results of scanning each file in the archive (True/False values)
    """
    all_files_results = []
    is_archive, archive_type = is_archive_file(archive_path)
    if not is_archive:
        print(f"File {archive_path} is not a recognized archive.")
        return

    print(f"\n=== Scanning archive {archive_path} (type: {archive_type}) ===")

    # First check the archive itself
    print(f"\n[*] Checking the archive itself:")
    malbazaarlookup(archive_path)

    # Now extract and scan all files inside
    with tempfile.TemporaryDirectory() as temp_dir:
        if not extract_archive(archive_path, temp_dir):
            print("Error extracting the archive.")
            return

        # Scan each file in the archive
        print(f"\n[*] Scanning archive contents:")
        for root, _, files in os.walk(temp_dir):
            for file in files:
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, temp_dir)

                print(f"\n--- Checking file: {rel_path} ---")

                # Check if this is a nested archive
                nested_is_archive, nested_type = is_archive_file(file_path)
                if nested_is_archive:
                    print(f"[!] Found nested archive of type {nested_type}!")
                    return scan_archive_files(file_path)  # Recursively scan nested archive
                else:
                    # Check regular file
                    all_files_results += [malbazaarlookup(file_path)]

    return all_files_results


def final_result_archive(file_path):
    """
    Scan an archive and determine if any of its contents were found in MalBazaar.

    Args:
        file_path (str): Path to the archive file

    Returns:
        bool: True if any file in the archive was found in MalBazaar, False otherwise
    """
    final_decision = scan_archive_files(file_path)
    for i in final_decision:
        if i == True:
            return True
    return False

# Main execution code would be placed here (currently commented out)
# print(final_result_archive(r"C:\code\python\school\VirusProject\files_to_check\advanced_suspicious_test.zip"))