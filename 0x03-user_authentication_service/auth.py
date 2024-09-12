#!/usr/bin/env python3
"""
Authentication module to handle user-related operations.
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Provides methods for authentication and user management."""

    def __init__(self):
        """Initialize Auth with a database connection."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register a new user with email and password.

        Args:
            email (str): User's email.
            password (str): User's password.

        Returns:
            User: The newly created user object.

        Raises:
            ValueError: If user with the email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)

    def valid_login(self, email: str, password: str) -> bool:
        """Validate login credentials.

        Args:
            email (str): User's email.
            password (str): User's password.

        Returns:
            bool: True if credentials are correct, False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a session for a user.

        Args:
            email (str): User's email.

        Returns:
            str: The session ID for the user.
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Retrieve a user based on session ID.

        Args:
            session_id (str): The session ID.

        Returns:
            User: The user associated with the session ID, or None if not found.
        """
        if session_id is None:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Terminate a user's session.

        Args:
            user_id (int): The user's ID.
        """
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generate a token for password reset.

        Args:
            email (str): User's email.

        Returns:
            str: Reset token.

        Raises:
            ValueError: If user does not exist.
        """
        try:
            user = self._db.find_user_by(email=email)
            token = _generate_uuid()
            self._db.update_user(user.id, reset_token=token)
            return token
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """Update user's password using reset token.

        Args:
            reset_token (str): The token for resetting password.
            password (str): New password to set.

        Raises:
            ValueError: If reset token is invalid.
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
        except NoResultFound:
            raise ValueError


def _hash_password(password: str) -> bytes:
    """Hash a password for storage.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generate a new UUID.

    Returns:
        str: A UUID string.
    """
    return str(uuid4())
