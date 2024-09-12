#!/usr/bin/env python3
"""
Database interaction module
"""
from sqlalchemy import create_engine, and_
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound
from user import Base, User

class Database:
    """Handles operations related to the User database."""

    def __init__(self) -> None:
        """Initialize the Database instance and create tables."""
        self._engine = create_engine("sqlite:///app_data.db")
        Base.metadata.drop_all(self._engine)  # Drops all tables if exist
        Base.metadata.create_all(self._engine)  # Creates all tables
        self._session = None

    @property
    def session(self) -> sessionmaker:
        """Get the active session, initializing if needed."""
        if self._session is None:
            SessionMaker = sessionmaker(bind=self._engine)
            self._session = SessionMaker()
        return self._session

    def create_user(self, email: str, password_hash: str) -> User:
        """Add a new user to the database."""
        new_user = User(email=email, hashed_password=password_hash)
        try:
            self.session.add(new_user)
            self.session.commit()
            return new_user
        except SQLAlchemyError:
            self.session.rollback()
            return None

    def get_user(self, **filters) -> User:
        """Retrieve a user by specified filters."""
        if not filters:
            raise ValueError("Must provide at least one filter criteria")

        try:
            user = self.session.query(User).filter_by(**filters).one()
            return user
        except NoResultFound:
            raise NoResultFound("No user found with provided filters.")
        except SQLAlchemyError as e:
            self.session.rollback()
            raise e

    def update_user(self, user_id: int, **updates) -> None:
        """Update user details by user_id."""
        user = self.get_user(id=user_id)
        for key, value in updates.items():
            if not hasattr(User, key):
                raise ValueError(f"Invalid attribute: {key}")
            setattr(user, key, value)
        self.session.commit()
