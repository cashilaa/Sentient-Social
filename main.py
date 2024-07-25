from dotenv import load_dotenv
from content_generation.generator import ContentGenerator
from content_generation.user_interests import UserInterestsManager
from content_moderation.moderator import ContentModerator
from bias_detection.bias_detector import BiasDetector
from feedback_loop.feedback_handler import FeedbackHandler
from user_auth.auth import UserAuth

load_dotenv()

class AIContentBot:
    def __init__(self):
        self.generator = ContentGenerator()
        self.moderator = ContentModerator()
        self.bias_detector = BiasDetector()
        self.feedback_handler = FeedbackHandler()
        self.user_interests = UserInterestsManager()
        self.user_auth = UserAuth()
        

    def generate_and_check_content(self, user_input, user_id, media_url=None):
        user_interests = self.user_interests.get_user_interests(user_id)
        
        # Generate content based on user input and interests
        prompt = f"Based on the following user input and interests, generate a social media post:\nUser Input: {user_input}\nUser Interests: {', '.join(user_interests)}"
        generated_content = self.generator.generate_content(prompt, user_interests)
        
        if media_url:
            generated_content += f" [Media: {media_url}]"
        
        # Moderate the generated content
        is_appropriate, moderation_result = self.moderator.moderate_content(generated_content)
        if not is_appropriate:
            return False, f"Generated content violates community guidelines: {moderation_result}"
        
        # Check for bias
        bias_detected, bias_result = self.bias_detector.detect_bias(generated_content)
        if bias_detected:
            return False, f"Generated content contains bias: {bias_result}"
        
        return True, generated_content

    def login(self, username, password):
        return self.user_auth.login(username, password)

    def generate_response(self, comment, user_id):
        user_interests = self.user_interests.get_user_interests(user_id)
        response = self.generator.generate_response(comment, user_interests)
        
        return self.generate_and_check_content(response, user_id)

    def handle_user_interaction(self, content, user_reaction):
        self.feedback_handler.add_feedback(content, user_reaction)
        if len(self.feedback_handler.feedback_data) % 100 == 0:
            analysis = self.feedback_handler.analyze_feedback()
            print("Feedback Analysis:", analysis)
            self.feedback_handler.update_model()

    def add_user_interests(self, user_id, interests):
        self.user_interests.add_user_interests(user_id, interests)

    def get_user_interests(self, user_id):
        return self.user_interests.get_user_interests(user_id)

    def remove_user_interest(self, user_id, interest):
        self.user_interests.remove_user_interest(user_id, interest)

# Example usage
if __name__ == "__main__":
    bot = AIContentBot()

    # Signup example
    success, message = bot.signup("user1", "password123")
    print(f"Signup result: {message}")

    # Login example
    success, message = bot.login("user1", "password123")
    print(f"Login result: {message}")

    # Add user interests after successful login
    if success:
        bot.add_user_interests("user1", ["AI", "technology", "innovation"])

    # Generate content (only if login was successful)
    if success:
        success, content1 = bot.generate_and_check_content("Write a post about the future of technology", "user1")
        print("Generated content for user1:", content1)

    success, content2 = bot.generate_and_check_content("Write a post about maintaining a healthy lifestyle", "user2")
    print("Generated content for user2:", content2)

    # Generate comment
    success, comment = bot.generate_comment(content1, "user2")
    print("Generated comment:", comment)

    # Generate response
    success, response = bot.generate_response(comment, "user1")
    print("Generated response:", response)

    # Handle user interactions
    bot.handle_user_interaction(content1, "positive")
    bot.handle_user_interaction(content2, "neutral")
    bot.handle_user_interaction(comment, "negative")
    bot.handle_user_interaction(response, "positive")

    # Get feedback analysis
    analysis = bot.feedback_handler.analyze_feedback()
    print("Feedback Analysis:", analysis)

    # Save and load feedback data
    bot.feedback_handler.save_feedback_data("feedback_data.json")
    bot.feedback_handler.load_feedback_data("feedback_data.json")