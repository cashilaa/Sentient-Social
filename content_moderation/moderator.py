import os
from dotenv import load_dotenv
import google.generativeai as genai
from .guidelines import COMMUNITY_GUIDELINES

load_dotenv()

class ContentModerator:
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-pro')

    def moderate_content(self, content):
        context = f"""
        Determine if the following content violates any of these community guidelines:
        {COMMUNITY_GUIDELINES}
        
        Content: {content}
        
        Respond with 'APPROPRIATE' if the content does not violate any guidelines, or 'INAPPROPRIATE' if it does.
        If inappropriate, briefly explain which guideline(s) it violates.
        """
        response = self.model.generate_content(context)
        return self._parse_moderation_result(response.text)

    def _parse_moderation_result(self, result):
        if "APPROPRIATE" in result.upper():
            return True, "Content is appropriate"
        elif "INAPPROPRIATE" in result.upper():
            return False, result.split("INAPPROPRIATE", 1)[1].strip()
        else:
            return False, "Moderation result unclear"