# Client launcher script for the Flask security analysis application
# This script handles starting the Flask server and opening the browser automatically

import webbrowser
import subprocess
import time
import sys
import os


def launch_client():
    """
    Launch the Flask client application

    This function:
    1. Starts the Flask application as a subprocess
    2. Waits briefly for the server to initialize
    3. Opens the application in the default web browser
    4. Keeps the process running until interrupted
    """
    print("🚀 Starting client Flask application...")

    # Start the Flask client as a subprocess using the current Python interpreter
    flask_process = subprocess.Popen([sys.executable, "client1.py"])

    # Wait for Flask to start up before trying to access it
    time.sleep(2)

    # Open the default web browser pointing to the Flask application's URL
    webbrowser.open("http://127.0.0.1:1234")

    print("✅ Flask client started. Web interface opened in browser.")
    print("Press Ctrl+C to shut down the client.")

    try:
        # Keep the script running until user interrupts with Ctrl+C
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        # Handle clean shutdown when user presses Ctrl+C
        print("\n🛑 Shutting down client...")
        flask_process.terminate()  # Send terminate signal to Flask process
        flask_process.wait()  # Wait for Flask process to fully terminate
        print("✅ Client shutdown complete.")


if __name__ == "__main__":
    # Execute the launch_client function when script is run directly
    launch_client()