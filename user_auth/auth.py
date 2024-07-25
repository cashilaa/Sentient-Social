import hashlib
import os
from dotenv import load_dotenv

load_dotenv()

class UserAuth:
    def __init__(self):
        self.users = {}  # In a real application, use a database instead
        self.secret_key = os.getenv("SECRET_KEY", "default_secret_key")

    def _hash_password(self, password):
        return hashlib.sha256((password + self.secret_key).encode()).hexdigest()

    def signup(self, username, password):
        if username in self.users:
            return False, "Username already exists"
        hashed_password = self._hash_password(password)
        self.users[username] = hashed_password
        return True, "User created successfully"

    def login(self, username, password):
        if username not in self.users:
            return False, "User not found"
        hashed_password = self._hash_password(password)
        if self.users[username] == hashed_password:
            return True, "Login successful"
        return False, "Incorrect password"