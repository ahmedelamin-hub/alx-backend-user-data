#!/usr/bin/env python3
"""
Database module handling all database operations.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
from user import User

Base = declarative_base()

class DB:
    """Database class for managing all SQL operations."""

    def __init__(self):
        """Initialize the database connection and session."""
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.create_all(self._engine)
        self._session_factory = sessionmaker(bind=self._engine)

    @property
    def _session(self) -> Session:
        """Generate a new session for the database operations.

        Returns:
            Session: A new SQLAlchemy session object.
        """
        return self._session_factory()

    def add_user(self, email: str, hashed_password: str) -> User:
        """Add a new user to the database.

        Args:
            email (str): User's email.
            hashed_password (str): Hashed password of the user.

        Returns:
            User: The newly created user object.
        """
        new_user = User(email=email, hashed_password=hashed_password)
        with self._session as session:
            session.add(new_user)
            session.commit()
            return new_user

    def find_user_by(self, **kwargs) -> User:
        """Find a user by arbitrary keyword arguments.

        Args:
            kwargs: Arbitrary keyword arguments representing user attributes.

        Returns:
            User: The user object matching the given criteria.

        Raises:
            NoResultFound: If no user is found with the provided criteria.
            InvalidRequestError: If the query is improperly formed.
        """
        with self._session as session:
            try:
                return session.query(User).filter_by(**kwargs).one()
            except NoResultFound:
                raise NoResultFound("No user found matching the criteria.")
            except InvalidRequestError:
                raise InvalidRequestError("Invalid query provided.")

    def update_user(self, user_id: int, **kwargs) -> None:
        """Update a user's information.

        Args:
            user_id (int): ID of the user to update.
            kwargs: Arbitrary keyword arguments representing fields to update.

        Raises:
            ValueError: If any key in kwargs is not a valid user attribute.
        """
        with self._session as session:
            try:
                user = self.find_user_by(id=user_id)
                for key, value in kwargs.items():
                    if not hasattr(user, key):
                        raise ValueError(f"Attribute '{key}' does not exist on the User model.")
                    setattr(user, key, value)
                session.commit()
            except NoResultFound:
                raise NoResultFound("User not found.")
