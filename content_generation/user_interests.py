class UserInterestsManager:
    def __init__(self):
        self.user_interests = {}

    def add_user_interests(self, user_id, interests):
        if user_id not in self.user_interests:
            self.user_interests[user_id] = set()
        self.user_interests[user_id].update(interests)

    def get_user_interests(self, user_id):
        return list(self.user_interests.get(user_id, []))

    def remove_user_interest(self, user_id, interest):
        if user_id in self.user_interests:
            self.user_interests[user_id].discard(interest)