#!/usr/bin/env python3
"""
User authentication logic
"""
import bcrypt
from db import Database
from user import User
from uuid import uuid4

class AuthService:
    """Provides authentication services for the application."""

    def __init__(self):
        self.db = Database()

    def register(self, email: str, password: str) -> User:
        """Register a new user with a hashed password."""
        try:
            self.db.get_user(email=email)
            raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            password_hash = self._encrypt_password(password)
            return self.db.create_user(email, password_hash)

    def validate_login(self, email: str, password: str) -> bool:
        """Check if the provided credentials are valid."""
        try:
            user = self.db.get_user(email=email)
            return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False

    def generate_session(self, email: str) -> str:
        """Generate a session for the user."""
        user = self.db.get_user(email=email)
        if not user:
            return None
        session_id = self._generate_uuid()
        self.db.update_user(user.id, session_id=session_id)
        return session_id

    def fetch_user_by_session(self, session_id: str) -> User:
        """Fetch user linked to the given session_id."""
        if not session_id:
            return None
        try:
            return self.db.get_user(session_id=session_id)
        except NoResultFound:
            return None

    def terminate_session(self, user_id: int) -> None:
        """End a user's session."""
        self.db.update_user(user_id, session_id=None)

    def generate_password_reset_token(self, email: str) -> str:
        """Create a token for password reset purposes."""
        user = self.db.get_user(email=email)
        token = self._generate_uuid()
        self.db.update_user(user.id, reset_token=token)
        return token

    def modify_password(self, reset_token: str, new_password: str) -> None:
        """Update a user's password using a valid reset token."""
        user = self.db.get_user(reset_token=reset_token)
        new_password_hash = self._encrypt_password(new_password)
        self.db.update_user(user.id, hashed_password=new_password_hash, reset_token=None)

    def _encrypt_password(self, password: str) -> bytes:
        """Hash a plain password using bcrypt."""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def _generate_uuid(self) -> str:
        """Generate a unique identifier."""
        return str(uuid4())
