#!/usr/bin/env python3
"""Database management module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from user import Base, User

class DB:
    """Handles database operations"""
    
    def __init__(self) -> None:
        """Sets up new DB instance"""
        self._engine = create_engine("sqlite:///a.db")
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Cached session handler"""
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a user to the database
           Args:
               email: user's email
               hashed_password: user's hashed password
           Returns:
               The created user object
        """
        session = self._session
        try:
            user_instance = User(email=email, hashed_password=hashed_password)
            session.add(user_instance)
            session.commit()
        except Exception:
            session.rollback()
            user_instance = None
        return user_instance

    def find_user_by(self, **kwargs) -> User:
        """Finds user with specific attributes
           Args:
               kwargs: key-value pairs for filtering
           Returns:
               User object if found
        """
        attributes, values = [], []
        for key, value in kwargs.items():
            if not hasattr(User, key):
                raise InvalidRequestError()
            attributes.append(getattr(User, key))
            values.append(value)

        query = self._session.query(User)
        user_found = query.filter(tuple_(*attributes).in_([tuple(values)])).first()
        if not user_found:
            raise NoResultFound()
        return user_found

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates user attributes
           Args:
               user_id: unique user identifier
           """
        user = self.find_user_by(id=user_id)
        for key, value in kwargs.items():
            if not hasattr(User, key):
                raise ValueError
            setattr(user, key, value)
        self._session.commit()
