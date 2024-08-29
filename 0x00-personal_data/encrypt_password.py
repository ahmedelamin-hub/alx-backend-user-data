#!/usr/bin/env python3
"""
Module for handling password encryption and validation using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password with a salt using bcrypt.
    
    Args:
        password (str): The plain text password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validate that the provided password matches the hashed password.
    
    Args:
        hashed_password (bytes): The hashed password.
        password (str): The plain text password to verify.

    Returns:
        bool: True if the password matches the hashed password, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
