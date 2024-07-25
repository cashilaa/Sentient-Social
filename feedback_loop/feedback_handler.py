import json
from collections import defaultdict

class FeedbackHandler:
    def __init__(self):
        self.feedback_data = []
        self.content_performance = defaultdict(lambda: {'positive': 0, 'negative': 0, 'neutral': 0})

    def add_feedback(self, content, user_reaction):
        self.feedback_data.append({"content": content, "reaction": user_reaction})
        self.content_performance[content][user_reaction] += 1

    def analyze_feedback(self):
        total_feedback = len(self.feedback_data)
        positive_feedback = sum(1 for item in self.feedback_data if item['reaction'] == 'positive')
        negative_feedback = sum(1 for item in self.feedback_data if item['reaction'] == 'negative')

        analysis = {
            "total_feedback": total_feedback,
            "positive_percentage": (positive_feedback / total_feedback) * 100 if total_feedback > 0 else 0,
            "negative_percentage": (negative_feedback / total_feedback) * 100 if total_feedback > 0 else 0,
            "top_performing_content": self._get_top_performing_content(5),
            "worst_performing_content": self._get_worst_performing_content(5)
        }

        return analysis

    def _get_top_performing_content(self, n):
        sorted_content = sorted(
            self.content_performance.items(),
            key=lambda x: (x[1]['positive'] - x[1]['negative'], x[1]['positive']),
            reverse=True
        )
        return [{"content": k, "performance": v} for k, v in sorted_content[:n]]

    def _get_worst_performing_content(self, n):
        sorted_content = sorted(
            self.content_performance.items(),
            key=lambda x: (x[1]['negative'] - x[1]['positive'], x[1]['negative']),
            reverse=True
        )
        return [{"content": k, "performance": v} for k, v in sorted_content[:n]]

    def update_model(self):
        # In a real implementation, this method would use the feedback data to fine-tune the model
        # For now, we'll just print a message indicating that the model would be updated
        print("Model update simulation: Using feedback data to improve content generation")
        
    def save_feedback_data(self, filename):
        with open(filename, 'w') as f:
            json.dump(self.feedback_data, f)

    def load_feedback_data(self, filename):
        with open(filename, 'r') as f:
            self.feedback_data = json.load(f)
        # Rebuild content_performance from loaded data
        self.content_performance = defaultdict(lambda: {'positive': 0, 'negative': 0, 'neutral': 0})
        for item in self.feedback_data:
            self.content_performance[item['content']][item['reaction']] += 1