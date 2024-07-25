import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

class BiasDetector:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def detect_bias(self, content):
        context = f"""
        Analyze the following content for potential biases related to race, gender, age, or other protected characteristics:
        
        {content}
        
        Respond with 'NO BIAS DETECTED' if no significant biases are found.
        If biases are detected, briefly explain what they are and how they manifest in the content.
        """
        try:
            response = self.model.generate_content(context)
            if not response.text:
                return True, "Bias detection failed due to safety filters. The content may contain inappropriate material."
            return self._parse_bias_result(response.text)
        except Exception as e:
            return True, f"An error occurred during bias detection: {str(e)}"

    def _parse_bias_result(self, result):
        if "NO BIAS DETECTED" in result.upper():
            return False, "No significant biases detected"
        else:
            return True, result.strip()
        
        