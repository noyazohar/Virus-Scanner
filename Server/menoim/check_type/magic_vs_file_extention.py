"""
File Extension Validator
-----------------------
A tool for validating file extensions by comparing them with the actual file type
detected using magic numbers and MIME types.

Features:
- Detects file types using magic numbers
- Maps MIME types to expected file extensions
- Validates if a file's extension matches its actual content type
- Supports a wide range of file formats including documents, images, videos, archives, etc.

Usage:
    validate_file_extension(file_path) -> Returns True if the extension doesn't match expected type
"""

import magic
import mimetypes
import os

# Extended dictionary with custom MIME type to file extension mappings
CUSTOM_EXTENSIONS = {
    # Documents
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/pdf": ".pdf",
    "text/plain": ".txt",
    "text/csv": ".csv",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.oasis.opendocument.text": ".odt",
    "application/rtf": ".rtf",

    # Code and script files
    "text/x-python": ".py",
    "text/javascript": ".js",
    "application/json": ".json",
    "text/html": ".html",
    "text/css": ".css",
    "application/x-sh": ".sh",
    "application/xml": ".xml",

    # Executable files
    "application/x-msdownload": ".exe",
    "application/vnd.android.package-archive": ".apk",
    "application/x-dosexec": ".exe",
    "application/x-mach-binary": ".app",
    "application/x-executable": ".out",

    # Image files
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/gif": ".gif",
    "image/bmp": ".bmp",
    "image/tiff": ".tiff",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",

    # Video files
    "video/mp4": ".mp4",
    "video/x-msvideo": ".avi",
    "video/x-matroska": ".mkv",
    "video/quicktime": ".mov",
    "video/webm": ".webm",

    # Audio files
    "audio/mpeg": ".mp3",
    "audio/ogg": ".ogg",
    "audio/wav": ".wav",
    "audio/x-flac": ".flac",
    "audio/aac": ".aac",

    # Compressed and archive files
    "application/zip": ".zip",
    "application/x-rar-compressed": ".rar",
    "application/x-rar": ".rar",
    "application/gzip": ".gz",
    "application/x-7z-compressed": ".7z",
    "application/x-tar": ".tar",
    "application/x-bzip2": ".bz2",

    # Database files
    "application/x-sqlite3": ".sqlite",
    "application/vnd.ms-access": ".mdb",
    "application/vnd.oasis.opendocument.spreadsheet": ".ods",

    # ISO and disk image files
    "application/x-iso9660-image": ".iso",
    "application/x-apple-diskimage": ".dmg",

    # CAD and engineering files
    "application/acad": ".dwg",
    "image/vnd.dxf": ".dxf",

    # Game files
    "application/x-msdos-program": ".com",
    "application/x-nintendo-nes-rom": ".nes",
    "application/x-sega-genesis-rom": ".gen",
    "application/x-snes-rom": ".sfc",

    # Other files
    "application/x-cod": ".cod",
    "application/octet-stream": ".bin",
}


def get_magic_nums(file_path: str) -> str:
    """
    Identifies file type using magic numbers.

    Args:
        file_path (str): Path to the file to examine

    Returns:
        str: MIME type string representing the detected file type
    """
    mime = magic.Magic(mime=True)
    raw_result = mime.from_file(file_path)

    # Handle byte string result and convert to string if needed
    if isinstance(raw_result, bytes):
        return raw_result.decode("utf-8", errors="replace")
    return raw_result


def get_expected_extension(detected_mime: str) -> str:
    """
    Returns the expected file extension based on the MIME type.

    Args:
        detected_mime (str): MIME type of the file

    Returns:
        str or None: Expected file extension including the dot (e.g. '.pdf'),
                     or None if no match is found
    """
    # First check in our custom lookup table
    expected_extension = CUSTOM_EXTENSIONS.get(detected_mime)

    # If not found in the custom table, try with mimetypes library
    if expected_extension is None:
        expected_extension = mimetypes.guess_extension(detected_mime)

    return expected_extension


def validate_file_extension(file_path: str) -> bool:
    """
    Checks if a file's extension matches its actual content type.

    This function detects the actual file type using magic numbers,
    then compares the file's extension with what would be expected
    for that file type.

    Args:
        file_path (str): Path to the file to validate

    Returns:
        bool: True if the extension doesn't match (potential spoofing),
              False if extension matches the content type
    """
    detected_mime = get_magic_nums(file_path)
    file_extension = os.path.splitext(file_path)[1].lower()
    expected_extension = get_expected_extension(detected_mime)

    print(f"🔍 MIME Detected: {detected_mime}")
    print(f"📂 File Extension: {file_extension}")
    print(f"📌 Expected Extension: {expected_extension}")

    # If we couldn't find an expected extension, perform partial matching
    if expected_extension is None:
        print("⚠️ Could not determine appropriate extension. Performing manual check...")
        return detected_mime.startswith("text/") and file_extension in {".txt", ".csv", ".log", ".py"}

    # Flexible comparison between extensions
    if file_extension == expected_extension or file_extension in CUSTOM_EXTENSIONS.values():
        return False
    return True

# Example usage (currently commented out)
# print(validate_file_extension(r"C:\code\python\school\VirusProject\files_to_check\advanced_suspicious_test.zip"))