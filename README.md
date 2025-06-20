This project is a robust file scanning and analysis system based on a Server-Client architecture, developed in Python with SQL for database management and HTML for the client’s web interface. The primary goal of the system is to determine whether files uploaded by clients are malicious or benign (B9) using multiple specialized detection engines. The server is designed to handle multiple concurrent client connections (multi-client) and to perform analyses in parallel using threads, ensuring high performance and scalability.
The system supports all file types, including archive files such as archive files, which are automatically extracted and analyzed in depth.

System Workflow
1. Database Check
To optimize performance, the server first checks whether the hash of each uploaded file exists in its local database, which stores records of previously analyzed files. This database is updated in real time to ensure that identical files are not re-scanned unnecessarily.
2. Multi-Engine Analysis
If a file is not found in the database, it is processed using three independent detection engines, which run in parallel:
•	MalwareBazaar API Engine
This engine queries the MalwareBazaar API to check whether the file’s hash appears in an external repository of known malware samples.
•	Data Analysis Engine
This engine performs static analysis based on three sub-checks:
1.	Keyword Search: Scans the file’s content for suspicious words or script patterns, using a predefined list of keywords with associated risk levels.
2.	Suspicious Imports Detection: Identifies suspicious libraries or modules that may indicate harmful functionality.
3.	Entropy Calculation: Measures the file’s entropy to detect high randomness, which may suggest encryption or compression techniques commonly used to hide malicious code.
•	Magic Number vs. Extension Engine
This engine compares the file’s internal magic number with its declared extension to detect inconsistencies, which can reveal disguised or misleading file types.
Each engine’s results are weighted differently in the final risk score, producing a comprehensive risk assessment for each file.

Client-Side Functionality
The client side consists of a web-based user interface that allows users to:
•	Upload one or more files for scanning.
•	Receive a detailed risk score for each file detected as potentially malicious.
•	View additional information about the file and access direct links to trusted external security resources, such as VirusTotal and MalwareBazaar, for further analysis and guidance.

Key Features
•	Supports multiple simultaneous clients through multi-threaded server processing.
•	Real-time updated database to prevent redundant scans and save resources.
•	Parallel execution of detection engines for quick and accurate results.
•	Full support for all file types, including compressed archives.
•	User-friendly web interface providing clear and actionable scan results.
•	Detailed risk reports with references to reputable security platforms for extended insights.

