#!/usr/bin/env python3
"""
Handles user authentication
"""
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound

class Auth:
    """Handles authentication logic and database interaction"""

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user
           Args:
               email: user's email
               password: plaintext password
           Returns:
               The created user object
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if credentials match any user
           Args:
               email: user's email
               password: user's password
           Returns:
               True if credentials are valid, otherwise False
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        """Generates a new session ID for user
           Args:
               email: user's email
           Returns:
               session ID as string
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """Gets user by session ID
           Args:
               session_id: user's session ID
           Returns:
               Corresponding User object or None
        """
        if not session_id:
            return None
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Removes the session ID from a user"""
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user
           Args:
               email: user's email
           Returns:
               A unique token
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates user password using a reset token
           Args:
               reset_token: token for password reset
               password: new password
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        self._db.update_user(user.id, hashed_password=_hash_password(password), reset_token=None)

def _hash_password(password: str) -> bytes:
    """Converts plaintext password to hashed bytes
       Args:
           password: user's plaintext password
       Returns:
           Hashed password as bytes
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def _generate_uuid() -> str:
    """Creates a new UUID string
       Returns:
           UUID as a string
    """
    return str(uuid4())
