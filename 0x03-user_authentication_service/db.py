#!/usr/bin/env python3
"""
This module contains the DB class for managing all database interactions
related to user authentication, session management, and password reset functionalities.
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import NoResultFound
from user import Base, User


class DB:
    """DB class to manage interactions with the database."""

    def __init__(self):
        """Initialize a new DB instance with a SQLite database."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.create_all(self._engine)
        self._session_maker = sessionmaker(bind=self._engine)

    def _session(self) -> Session:
        """Create a new session."""
        return self._session_maker()

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        Adds a new user to the database.

        Args:
            email (str): The email of the new user.
            hashed_password (str): The hashed password of the new user.

        Returns:
            User: The newly created user object.
        """
        session = self._session()
        new_user = User(email=email, hashed_password=hashed_password)
        session.add(new_user)
        session.commit()
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """
        Finds a user by arbitrary filter conditions.

        Args:
            **kwargs: Arbitrary keyword arguments representing filter conditions.

        Returns:
            User: The user object that matches the filter criteria.

        Raises:
            NoResultFound: If no user is found matching the criteria.
        """
        session = self._session()
        try:
            user = session.query(User).filter_by(**kwargs).one()
            return user
        except NoResultFound:
            raise NoResultFound("No user found with the provided criteria.")
        finally:
            session.close()

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        Updates the user record with the given fields.

        Args:
            user_id (int): The ID of the user to update.
            **kwargs: Arbitrary keyword arguments representing fields to update.

        Raises:
            ValueError: If any of the provided fields are invalid.
        """
        session = self._session()
        try:
            user = session.query(User).filter_by(id=user_id).one()
            for key, value in kwargs.items():
                if not hasattr(user, key):
                    raise ValueError(f"Invalid attribute: {key}")
                setattr(user, key, value)
            session.commit()
        except NoResultFound:
            raise NoResultFound(f"User with id {user_id} not found.")
        finally:
            session.close()
