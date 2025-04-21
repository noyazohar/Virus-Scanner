import sqlite3
import os

# Path to the SQLite database file
DB_PATH = "files_db.sqlite"


def create_database():
    """
    Create the database and files table if it doesn't exist.

    This function checks if the database exists, connects to it (creating it if necessary),
    creates the files table with columns for storing file analysis results, and adds an index
    for faster searches. It prints a status message indicating whether the database
    was created or already existed.
    """
    db_exists = os.path.exists(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Create table with columns for various malware analysis scores
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        file_hash TEXT UNIQUE NOT NULL,
        is_malicious BOOLEAN NOT NULL,
        malicious_score REAL CHECK(malicious_score BETWEEN 0 AND 100),
        magic_score REAL CHECK(magic_score BETWEEN 0 AND 100),
        maleware_bazzar_score REAL CHECK(maleware_bazzar_score BETWEEN 0 AND 100),
        data_analysis_score REAL CHECK(data_analysis_score BETWEEN 0 AND 100),
        detection_mechanisms TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # Create index for faster searches by file hash
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_file_hash ON files(file_hash)")

    conn.commit()
    conn.close()

    if db_exists:
        print("✅ Database exists and is accessible")
    else:
        print("✅ New database created successfully!")


def get_db_connection():
    """
    Creates a new database connection for each call.

    This function ensures the database exists by calling create_database() if necessary,
    then returns a connection object to the SQLite database.

    Returns:
        sqlite3.Connection: A connection to the SQLite database
    """
    if not os.path.exists(DB_PATH):
        create_database()
    return sqlite3.connect(DB_PATH)


def get_file_info(file_hash):
    """
    Check if a file exists in the database and return its analysis information if found.

    Args:
        file_hash (str): The hash of the file to search for

    Returns:
        tuple: Contains (malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms)
              If the file is not found, returns default values (0, 0, 0, 0, "No detection mechanisms found")
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms 
        FROM files WHERE file_hash = ?
    """, (file_hash,))
    result = cursor.fetchone()
    conn.close()

    if result:
        return result
    else:
        # Returns default values to prevent issues in HTML display
        return (0, 0, 0, 0, "No detection mechanisms found")


def insert_file(file_hash, is_malicious, malicious_score, magic_score, maleware_bazzar_score, data_analysis_score,
                detection_mechanisms):
    """
    Add a new file to the database or update an existing one.

    This function attempts to insert a new file record. If the file hash already exists,
    it updates the existing record instead. All scores are converted to floats and the
    is_malicious boolean is converted to an integer for SQLite storage.

    Args:
        file_hash (str): Unique hash identifier for the file
        is_malicious (bool): Whether the file is determined to be malicious
        malicious_score (float): Overall malicious score (0-100)
        magic_score (float): Magic file analysis score (0-100)
        maleware_bazzar_score (float): Malware Bazaar analysis score (0-100)
        data_analysis_score (float): Data content analysis score (0-100)
        detection_mechanisms (str): Description of detection mechanisms that identified the file
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Ensure all scores are valid floats
        malicious_score = float(malicious_score)
        magic_score = float(magic_score)
        maleware_bazzar_score = float(maleware_bazzar_score)
        data_analysis_score = float(data_analysis_score)

        # Convert boolean to integer for SQLite
        is_malicious_int = 1 if is_malicious else 0

        cursor.execute("""
        INSERT INTO files (file_hash, is_malicious, malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (file_hash, is_malicious_int, malicious_score, magic_score, maleware_bazzar_score, data_analysis_score,
              detection_mechanisms))
        conn.commit()
        print(f"✅ File {file_hash[:8]}... added to database successfully!")
    except sqlite3.IntegrityError:
        print(f"⚠️ File {file_hash[:8]}... already exists in the database!")
        # Update the existing record instead
        try:
            cursor.execute("""
            UPDATE files 
            SET is_malicious = ?, malicious_score = ?, magic_score = ?, maleware_bazzar_score = ?, data_analysis_score = ?, detection_mechanisms = ?
            WHERE file_hash = ?
            """, (is_malicious_int, malicious_score, magic_score, maleware_bazzar_score, data_analysis_score,
                  detection_mechanisms, file_hash))
            conn.commit()
            print(f"✅ File {file_hash[:8]}... updated in the database!")
        except Exception as e:
            print(f"❌ Error updating file in the database: {e}")
    except Exception as e:
        print(f"❌ Error adding file to the database: {e}")
    finally:
        conn.close()


def get_all_files(limit=100):
    """
    Retrieve all files from the database, limited to a certain number.

    Args:
        limit (int, optional): Maximum number of files to retrieve. Defaults to 100.

    Returns:
        list: List of tuples containing file information in the format:
              (file_hash, is_malicious, malicious_score, magic_score, maleware_bazzar_score,
              data_analysis_score, detection_mechanisms, timestamp)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT file_hash, is_malicious, malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms, timestamp 
    FROM files 
    ORDER BY timestamp DESC 
    LIMIT ?
    """, (limit,))
    results = cursor.fetchall()
    conn.close()
    return results


def clear_database():
    """
    Clear all records from the files table.

    This function deletes all file records from the database but keeps the table structure.
    It prints a message confirming that all records were deleted.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM files")
    conn.commit()
    conn.close()
    print("🗑️ All records deleted from the database!")


if __name__ == "__main__":
    create_database()
    print("This script can be used to create the database")
    print("Run 'python db_operations.py' to create a new database (if not exist)")