# Flask application for file upload and analysis
# This application allows users to upload files which are then sent to an analysis service
# through the Client class that provides security scoring and analysis

from flask import Flask, request, render_template, jsonify
import os
from Client import Client

app = Flask(__name__)  # Initialize Flask application
UPLOAD_FOLDER = "client_uploads"  # Define directory for uploaded files
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Create upload directory if it doesn't exist
client = Client()  # Initialize the Client class that handles file analysis


@app.route("/", methods=["GET", "POST"])
def upload_file():
    """
    Main route handler for both displaying the upload form (GET) and
    processing file uploads (POST)

    Returns:
        - For GET requests: Renders the upload form
        - For POST requests: Processes the file and returns analysis results
    """
    if request.method == "POST":
        try:
            # Check if file exists in the request
            if 'file' not in request.files:
                return jsonify({"status": "error", "message": "No file found in request."}), 400

            file = request.files['file']
            # Check if a file was actually selected
            if file.filename == '':
                return jsonify({"status": "error", "message": "No file selected"}), 400

            # Save the uploaded file to the upload directory
            file_path = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(file_path)

            # Send the file for analysis using the Client
            results = client.send_files_with_content([file_path])

            # Handle errors from the analysis service
            if "error" in results:
                return jsonify({"status": "error", "message": results["error"]}), 500

            # Extract results specific to the uploaded file
            file_result = results.get(file.filename, None)
            if not file_result:
                return jsonify({"status": "error", "message": "No results returned for file"}), 500

            # Unpack the security analysis scores and detection data
            malicious_score, magic_score, maleware_bazzar_score, data_analysis_score, detection_mechanisms = file_result

            # Render the results template with the analysis data
            return render_template("result.html",
                                   filename=file.filename,
                                   malicious_score=malicious_score,
                                   magic_score=magic_score,
                                   maleware_bazzar_score=maleware_bazzar_score,
                                   data_analysis_score=data_analysis_score,
                                   detection_mechanisms=detection_mechanisms)

        except Exception as e:
            # Handle any unexpected errors
            return jsonify({"status": "error", "message": "Internal Server Error: " + str(e)}), 500

    # For GET requests, render the upload form
    return render_template("index.html")


if __name__ == "__main__":
    # Run the Flask application on localhost port 1234
    app.run(host="127.0.0.1", port=1234, debug=False)