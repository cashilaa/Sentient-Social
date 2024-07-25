import os
from dotenv import load_dotenv
import google.generativeai as genai

load_dotenv()

class ContentGenerator:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def generate_content(self, prompt, user_interests):
        try:
            interests_str = ", ".join(user_interests)
            context = f"{prompt}\nConsider the following interests: {interests_str}"
            response = self.model.generate_content(context)
            if not response.text:
                return "Content generation failed. Please try again."
            return response.text.strip()
        except Exception as e:
            print(f"Error in generate_content: {str(e)}")
            return f"An error occurred during content generation: {str(e)}"