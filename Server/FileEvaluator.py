import hashlib
import os
import threading
import sys
import logging
import tarfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Dictionary of archive file signatures
ARCHIVE_SIGNATURES = {
    b'PK\x03\x04': 'zip',
    b'\x1F\x8B\x08': 'gzip',
    b'BZh': 'bzip2',
    b'\xFD\x37\x7A\x58\x5A\x00': 'xz',
    b'Rar!\x1A\x07\x00': 'rar',
    b'Rar!\x1A\x07\x01\x00': 'rar5',
    b'\x75\x73\x74\x61\x72': 'tar'
}

# Add paths to sys.path to allow module imports
path1 = r"C:\\code\\python\\school\\VirusProject\\Server\\menoim\\API_bazaar"
path2 = r"C:\\code\\python\\school\\VirusProject\\Server\\menoim\\check_type"
path3 = r"C:\\code\\python\\school\\VirusProject\\Server\\menoim\\data_analysis"
path4 = r"C:\\code\\python\\school\\VirusProject\\Server"

sys.path.append(path1)
sys.path.append(path2)
sys.path.append(path3)
sys.path.append(path4)

csv_path = r"C:\\code\\python\\school\\VirusProject\\Server\\data_analysis\\suspicious_keywords_risk.csv"

# Import custom modules
from bazaar import scan_archive_files, malbazaarlookup, final_result_archive
from magic_vs_file_extention import validate_file_extension
from analysis_any_type_of_file import scan
from db_operations import get_db_connection, get_file_info, insert_file

def is_archive_file(file_path):
    """
    Check whether a file is an archive based on its magic signature or using tarfile module.

    Args:
        file_path (str): The path to the file.

    Returns:
        tuple: (is_archive (bool), archive_type (str or None))
    """
    try:
        with open(file_path, "rb") as f:
            magic_bytes = f.read(16)
            for signature, archive_type in ARCHIVE_SIGNATURES.items():
                if magic_bytes.startswith(signature):
                    return True, archive_type
            if tarfile.is_tarfile(file_path):
                return True, 'tar'
            return False, None
    except Exception as e:
        logging.error(f"Error checking archive signature: {e}")
        return False, None

def get_file_hash(file_path):
    """
    Generate SHA-256 hash of a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        str: SHA-256 hash in hexadecimal format.
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

class FileEvaluator:
    """
    Class to evaluate a file using multiple detection mechanisms and produce a final verdict.
    """
    def __init__(self, file_path, weight_magic=0.2, weight_malware=0.5, weight_script=0.3, threshold=50):
        """
        Initialize the FileEvaluator.

        Args:
            file_path (str): Path to the file to evaluate.
            weight_magic (float): Weight for file extension validation.
            weight_malware (float): Weight for malware signature check.
            weight_script (float): Weight for content-based data analysis.
            threshold (float): Threshold score to consider a file malicious.
        """
        self.file_path = file_path
        self.weight_magic = weight_magic
        self.weight_malware = weight_malware
        self.weight_script = weight_script
        self.threshold = threshold
        self.is_archive, self.archive_type = is_archive_file(self.file_path)

    def run_engines_in_parallel(self):
        """
        Run the magic, malware, and data analysis engines in parallel.

        Returns:
            dict: Results from each detection engine.
        """
        results = {}
        if self.is_archive:
            threads = [
                threading.Thread(target=lambda: results.update({"magic_check": validate_file_extension(self.file_path)})),
                threading.Thread(target=lambda: results.update({"malware_check": final_result_archive(self.file_path)})),
                threading.Thread(target=lambda: results.update({"data_analysis": scan(self.file_path, csv_path)})),
            ]
        else:
            threads = [
                threading.Thread(target=lambda: results.update({"magic_check": validate_file_extension(self.file_path)})),
                threading.Thread(target=lambda: results.update({"malware_check": malbazaarlookup(self.file_path)})),
                threading.Thread(target=lambda: results.update({"data_analysis": scan(self.file_path, csv_path)})),
            ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        print("Results from engines:", results)
        return results

    def _run_data_analysis(self, results):
        """
        Run data analysis on the file, handling both archive and regular files.

        Args:
            results (dict): Dictionary to update with analysis results.
        """
        if self.is_archive:
            print(f"🔍 Analyzing archive file: {os.path.basename(self.file_path)} (Type: {self.archive_type})")
            overall_score, detailed_results = scan(
                path=self.file_path,
                csv_path="C:\\code\\python\\school\\VirusProject\\menoim\\data_analysis\\suspicious_keywords_risk.csv"
            )
            results.update({
                "data_analysis": overall_score,
                "archive_details": detailed_results
            })
        else:
            score, _ = scan(
                path=self.file_path,
                csv_path="C:\\code\\python\\school\\VirusProject\\menoim\\data_analysis\\suspicious_keywords_risk.csv"
            )
            results.update({"data_analysis": score})

    def evaluate(self):
        """
        Evaluate the file and return scores from different engines with a final verdict.

        Returns:
            tuple: Final score, magic score, malware score, data analysis score, and verdict.
        """
        file_hash = get_file_hash(self.file_path)
        cached_result = get_file_info(file_hash)
        print("chchch", cached_result)
        if cached_result and any(float(score) > 0 for score in cached_result[:-1] if score is not None):
            print(f"🔍 Found cached result for {file_hash[:8]}...")
            malicious_score = float(cached_result[0]) if cached_result[0] is not None else 0.0
            magic_score = float(cached_result[1]) if cached_result[1] is not None else 0.0
            maleware_bazzar_score = float(cached_result[2]) if cached_result[2] is not None else 0.0
            data_analysis_score = float(cached_result[3]) if cached_result[3] is not None else 0.0
            detection_mechanisms = cached_result[4] if cached_result[4] is not None else "No detection mechanisms found"
            print("malicious_score", malicious_score)
            print("magic_score", magic_score)
            print("maleware_bazzar_scoree", maleware_bazzar_score)
            print("data_analysis_score", malicious_score)
            return malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms

        print(f"🔄 Running new evaluation for file {os.path.basename(self.file_path)}")
        results = self.run_engines_in_parallel()

        final_score = 0.0
        magic_score = 0.0
        maleware_bazzar_score = 0.0
        data_analysis_score = 0.0
        archive_details = None

        if results.get("magic_check"):
            magic_score = float(self.weight_magic * 100)
            final_score += magic_score

        if results.get("malware_check"):
            maleware_bazzar_score = float(self.weight_malware * 100)
            final_score += maleware_bazzar_score

        try:
            data_analysis_value = results.get("data_analysis", 0)
            if data_analysis_value is not None:
                if data_analysis_value > 1:
                    data_analysis_value = 1
                data_analysis_score = float(data_analysis_value) * self.weight_script * 100
                final_score += data_analysis_score

            if self.is_archive:
                archive_details = results.get("archive_details")
        except (ValueError, TypeError) as e:
            print(f"Error converting data_analysis score: {e}")
            data_analysis_score = 0.0

        final_score = round(float(final_score), 1)
        magic_score = round(float(magic_score), 1)
        maleware_bazzar_score = round(float(maleware_bazzar_score), 1)
        data_analysis_score = round(float(data_analysis_score), 1)

        print(
            f"Scores: Final={final_score}, Magic={magic_score}, Malware Bazaar={maleware_bazzar_score}, Data Analysis={data_analysis_score}")

        is_malicious = final_score >= self.threshold
        if final_score <= 29.0:
            verdict = " The file is safe "
        elif final_score >= 30 and final_score <= 49:
            verdict = " The file is mostly safe "
        else:
            verdict = " The file is not safe, watch out! "

        if self.is_archive and archive_details:
            num_files = len(archive_details.get('files', []))
            verdict += f"\n📦 Archive contains {num_files} file(s)"

            high_risk_files = []
            for file_info in archive_details.get('files', []):
                file_score = file_info.get('data', {}).get('malicious_score', 0)
                if file_score > 0.5:
                    high_risk_files.append(file_info.get('file', 'unknown'))

            if high_risk_files:
                verdict += f"\n⚠️ {len(high_risk_files)} suspicious file(s) found in archive:"
                for file in high_risk_files[:3]:
                    verdict += f"\n - {file}"
                if len(high_risk_files) > 3:
                    verdict += f"\n - ...and {len(high_risk_files) - 3} more"

        print(verdict)

        insert_file(file_hash, is_malicious, final_score, magic_score, maleware_bazzar_score, data_analysis_score, verdict)

        return final_score, magic_score, maleware_bazzar_score, data_analysis_score, verdict
