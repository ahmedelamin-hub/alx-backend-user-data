#!/usr/bin/env python3
"""
This module contains the Auth class for user authentication, session management,
and password reset functionalities.
"""

from uuid import uuid4
from typing import Union
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from hashlib import md5


class Auth:
    """Auth class to manage the authentication, sessions, and password management."""

    def __init__(self):
        """Initialize the Auth class with a database instance."""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user."""
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            hashed_password = md5(password.encode()).hexdigest()
            user = self._db.add_user(email, hashed_password)
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if the provided login details are valid."""
        try:
            user = self._db.find_user_by(email=email)
            return user.hashed_password == md5(password.encode()).hexdigest()
        except (NoResultFound, InvalidRequestError):
            return False

    def create_session(self, email: str) -> str:
        """Creates a new session for the user."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = str(uuid4())
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Gets a user from a session ID."""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys the user's session."""
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for a user."""
        try:
            user = self._db.find_user_by(email=email)
            reset_token = str(uuid4())
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except NoResultFound:
            raise ValueError("User does not exist.")

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using a reset token."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = md5(password.encode()).hexdigest()
            self._db.update_user(user.id, hashed_password=hashed_password, reset_token=None)
        except NoResultFound:
            raise ValueError("Invalid reset token.")
