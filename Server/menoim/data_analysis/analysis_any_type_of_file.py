import os
import zipfile
import csv
import math
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# List of suspicious imports and libraries in different programming languages
# Stored as bytes to enable searching in binary files
SUSPISIOUS_IMPORTS = [
    # --- Python - libraries that allow system and network access ---
    b'import os', b'import sys', b'import subprocess', b'import ctypes',
    b'import socket', b'import shutil', b'import requests', b'import urllib',
    b'from urllib import request',

    # --- C / C++ includes - headers for system and network control ---
    b'#include <windows.h>', b'#include <wininet.h>', b'#include <tlhelp32.h>',
    b'#include <psapi.h>', b'#include <winsock2.h>', b'#include <shellapi.h>',
    b'#include <process.h>', b'#include <shlobj.h>',

    # --- PowerShell / PE signatures - commands for remote file downloading ---
    b'Add-Type', b'New-Object Net.WebClient', b'Invoke-WebRequest',
    b'Import-Module', b'Get-Command', b'Register-ScheduledTask',

    # --- Java imports - network and encryption libraries ---
    b'import java.io', b'import java.net', b'import java.lang.reflect',
    b'import javax.crypto', b'import java.util.Base64',

    # --- JavaScript (Node.js) require - file system and network access ---
    b'require("child_process")', b'require(\'child_process\')',
    b'require("fs")', b'require("net")', b'require("http")', b'require("https")',

    # --- PHP includes - functions for code execution and server access ---
    b'include(', b'require(', b'require_once(', b'include_once(',
    b'use socket_create', b'use exec', b'use shell_exec', b'use base64_decode',

    # --- .NET / C# using - system and network access libraries ---
    b'using System.IO', b'using System.Net', b'using System.Reflection',
    b'using System.Diagnostics', b'using System.Management', b'using System.Runtime.InteropServices',

    # --- Dynamic library loading - enables runtime execution of malicious code ---
    b'LoadLibrary', b'GetProcAddress', b'dlopen', b'dlsym'
]


def check_if_zip(file_path):
    """
    Checks if the file starts with MZ (Windows executable file signature)

    Parameters:
        file_path (str): Path to the file to check

    Returns:
        boolean: True if the file starts with MZ, otherwise False

    Note:
        Despite the function name, it actually checks if the file is a PE (executable) file, not a ZIP
    """
    try:
        with open(file_path, "rb") as f:
            magic = f.read(2)
            return magic == b'MZ'
    except Exception as e:
        logging.error(f"Error checking MZ file: {e}")
        return False


def load_keywords_from_csv(csv_path):
    """
    Reads keywords and risk assessment from a CSV file

    Parameters:
        csv_path (str): Path to CSV file containing keywords and risk levels

    Returns:
        dict: Dictionary of keywords (key) and their corresponding risk levels (value)

    File structure:
        - First column: keyword
        - Second column: risk level (numeric)
        - First row is considered header and skipped
    """
    keywords = {}
    try:
        with open(csv_path, newline='', encoding="utf-8") as csvfile:
            reader = csv.reader(csvfile)
            next(reader, None)  # Skip header row
            for row in reader:
                if len(row) >= 2:
                    word = row[0].strip()
                    try:
                        risk_level = int(row[1].strip())
                        keywords[word] = risk_level
                    except ValueError:
                        continue  # Skip rows with invalid risk values
        return keywords
    except Exception as e:
        logging.error(f"Error loading keywords: {e}")
        return {}


def search_keywords_in_file(file_path, keywords, chunk_size=4096):
    """
    Checks if keywords from the list appear in the file

    Parameters:
        file_path (str): Path to the file to check
        keywords (dict): Dictionary of suspicious keywords and their risk levels
        chunk_size (int): Size of chunks to read for binary files

    Returns:
        dict: Dictionary containing only the words found in the file and their risk levels

    Note:
        - Attempts to read the file as text first
        - If that fails, reads as binary file and searches by chunks to save memory
    """
    found_keywords = {}
    try:
        # Try reading as text file
        with open(file_path, "r", encoding="utf-8") as file:
            content = file.read()
            found_keywords = {word: risk for word, risk in keywords.items() if word in content}
    except (UnicodeDecodeError, ValueError):
        # If binary file, search by bytes
        with open(file_path, "rb") as file:
            while chunk := file.read(chunk_size):
                for word, risk in keywords.items():
                    if word.encode() in chunk:
                        found_keywords[word] = risk

    return found_keywords


def calculate_risk(found_keywords, total_keywords):
    """
    Calculates the overall risk level percentage based on found keywords

    Parameters:
        found_keywords (dict): Dictionary of suspicious words found and their risk levels
        total_keywords (int): Total number of keywords in the database

    Returns:
        float: Ratio/percentage representing the calculated risk level

    Algorithm:
        - High risk keywords (80-100) get a weight of 80
        - Medium risk keywords (21-50) get a weight of 50
        - Low risk keywords get a weight of 20
        - The sum is divided by the total number of keywords
    """
    if not found_keywords:
        return 0  # If no suspicious words found, no risk

    detected_risk = 0
    for risk_level in found_keywords.values():
        if 80 <= risk_level <= 100:
            detected_risk += 80  # High risk
        elif 21 <= risk_level <= 50:
            detected_risk += 50  # Medium risk
        else:
            detected_risk += 20  # Low risk
    return detected_risk / total_keywords  # Calculate overall risk percentage


def analyze_script_risk(file_path, keywords):
    """
    Main function for the keyword search engine - performs the complete analysis process

    Parameters:
        file_path (str): Path to the file to analyze
        keywords (dict): Dictionary of suspicious keywords and their risk levels

    Returns:
        tuple: (risk percentage, total weighted risk)

    Process:
        1. Searches for suspicious words in the file
        2. Calculates the total weighted risk
        3. Calculates the risk percentage
    """
    total_keywords = len(keywords)
    found_words = search_keywords_in_file(file_path, keywords)

    # Calculate weighted sum of risk levels
    weighted_risk = sum(found_words.values()) if found_words else 0

    risk_percentage = calculate_risk(found_words, total_keywords)

    return risk_percentage, weighted_risk


def check_imports(file_path):
    """
    Checks if suspicious library/module imports exist in the file

    Parameters:
        file_path (str): Path to the file to check

    Returns:
        boolean: True if suspicious imports found, otherwise False

    Notes:
        - Binary string search (bytes) is performed
        - Supports both binary and text files
        - Displays the suspicious imports found
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

            # Convert suspicious imports to strings and check if they are in the file
            found_imports = [imp.decode('utf-8', errors='ignore') for imp in SUSPISIOUS_IMPORTS if imp in data]

            if found_imports:
                print("Imports found in file:")
                for imp in found_imports:
                    print(f"  • {imp}")
                return True
            else:
                print("No suspicious imports found in file.")
                return False

    except Exception as e:
        logging.error(f"Error checking imports: {e}")
        return False


def check_entropy(file_path):
    """
    Checks the entropy of the file (measure of data randomness)

    Parameters:
        file_path (str): Path to the file to check

    Returns:
        float: Entropy value of the file (0-8) or False in case of error

    Notes:
        - High entropy (close to 8) may indicate an encrypted or compressed file
        - High entropy in certain files may indicate malicious content
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            if not data:
                return False  # Empty file

            # Calculate byte distribution in the file
            byte_counts = [data.count(i) / len(data) for i in range(256)]

            # Shannon formula for entropy calculation
            entropy = -sum([p * (math.log2(p) if p > 0 else 0) for p in byte_counts])
            return entropy
    except Exception as e:
        logging.error(f"Error calculating entropy: {e}")
        return False


def scan_file(file_path, suspicious_keywords):
    """
    Scans a single file using all analysis engines and calculates a weighted risk score

    Parameters:
        file_path (str): Path to the file to scan
        suspicious_keywords (dict): Dictionary of suspicious keywords and their risk levels

    Returns:
        float: Weighted risk score (0-1)

    Process:
        1. Runs the keyword search engine
        2. Checks if the file is an executable (PE)
        3. Checks for suspicious imports
        4. Calculates entropy
        5. Weighs all results into a final score
    """
    # Engine 1: Keyword search
    keywords_suspicious, weighted_risk = analyze_script_risk(file_path, suspicious_keywords)

    # Engine 2: Additional checks
    magic_check = check_if_zip(file_path)  # Checks if it's a PE file
    import_check = check_imports(file_path)  # Checks suspicious imports
    entropy_check = check_entropy(file_path)  # Checks entropy

    # Print check details for debugging
    print(file_path)
    print(magic_check)
    print(import_check)
    print(entropy_check)
    print(keywords_suspicious)

    # Calculate weighted score based on results from all engines
    score = 0
    if keywords_suspicious:
        score += 0.3 * keywords_suspicious  # 30% of final score comes from keyword engine
    if import_check:
        score += 0.4  # 40% of score for finding suspicious imports
    if entropy_check:
        score += 0.3 * entropy_check  # 30% of score comes from entropy level (normalized)

    # Create object with all check results
    final_data = {
        'file': file_path,
        'check_if_zip': magic_check,  # Actually checks if it's an executable file
        'keywords_engine': {
            'is_suspicious': keywords_suspicious,
            'weighted_risk': weighted_risk
        },
        'imports_engine': import_check,
        'entropy_engine': entropy_check,
        'malicious_score': score
    }

    # Print results summary
    print("Scan Results:")
    print("-" * 50)
    print(f"File: {final_data['file']}")
    print(f"Keywords Engine:")
    print(f"  Suspicious: {final_data['keywords_engine']['is_suspicious']}")
    print(f"  Weighted Risk: {final_data['keywords_engine']['weighted_risk']}")
    print(f"Import Engine: {final_data['imports_engine']}")
    print(f"Entropy Engine: {final_data['entropy_engine']}")
    print(f"Final Score: {final_data['malicious_score']}")
    print("-" * 50)

    return score


def scan_zip(zip_path, suspicious_keywords):
    """
    Scans a ZIP archive by extracting all files and scanning each one individually

    Parameters:
        zip_path (str): Path to ZIP file
        suspicious_keywords (dict): Dictionary of suspicious keywords and their risk levels

    Returns:
        float: Average score of all files in the archive

    Process:
        1. Creates a temporary directory
        2. Extracts all files from the archive
        3. Scans each file individually
        4. Calculates average of all results
        5. Cleans up temporary files
    """
    temp_extract_path = "temp_scan_dir"
    os.makedirs(temp_extract_path, exist_ok=True)
    num_of_files = 0

    results = []

    # Extract all files from the archive
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(temp_extract_path)

    # Scan all files
    for root, _, files in os.walk(temp_extract_path):
        for file in files:
            num_of_files += 1
            file_path = os.path.join(root, file)
            results.append(scan_file(file_path, suspicious_keywords))

    # Clean up temporary files
    for root, _, files in os.walk(temp_extract_path, topdown=False):
        for file in files:
            os.remove(os.path.join(root, file))
        os.rmdir(root)

    # Calculate average of scan results
    return sum(results) / num_of_files if num_of_files > 0 else 0


def scan(path, csv_path):
    """
    Main function - checks if the path is a ZIP file or regular file and runs the appropriate function

    Parameters:
        path (str): Path to file or ZIP archive to scan
        csv_path (str): Path to CSV file containing suspicious keywords and risk levels

    Returns:
        float: Overall risk score (0-1) representing the likelihood the file is malicious
    """
    # Load suspicious keywords from CSV file
    suspicious_keywords = load_keywords_from_csv(csv_path)

    # Check if it's a ZIP file and route to the appropriate function
    if zipfile.is_zipfile(path):
        return scan_zip(path, suspicious_keywords)
    else:
        return scan_file(path, suspicious_keywords)

# Example code - currently commented out
# def main():
#   file_path = r"fake_malware.bin"  # Test file
#   csv_path = r"C:\code\python\school\VirusProject\Server\suspicious_keywords_risk.csv"  # Location of suspicious words file
#   result = scan(file_path, csv_path)
#   print(result)


# if __name__ == "__main__":
#   main()