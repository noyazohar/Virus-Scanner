from FileEvaluator import *


def new_check_of_file(file_path):
    """
    Evaluate a file for malicious content using the FileEvaluator module.
    This function serves as the main entry point for file analysis.

    Args:
        file_path (str): Path to the file to be evaluated

    Returns:
        tuple: A comprehensive analysis result containing:
            - final_score (float): The overall malicious score of the file
            - magic_score (float): Score based on file type analysis
            - malware_bazaar_score (float): Score based on malware database comparison
            - data_analysis_score (float): Score based on content analysis
            - verdict (str): Final classification of the file (e.g., "Clean", "Suspicious", "Malicious")
    """
    # Create an instance of FileEvaluator with the file path
    evaluator = FileEvaluator(file_path)

    # Evaluate the file (performs all analysis methods in one call)
    result = evaluator.evaluate()


    # Return the complete analysis result
    return result

