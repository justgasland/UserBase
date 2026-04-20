
import re
from flask import jsonify
from datetime import datetime
import uuid


def validate_email(email: str) -> bool:
    error=[]
    if not email:
        error.append({"field": "email", "message": "Email is required."})
    elif '@' not in email or '.' not in email:
        error.append({"field": "email", "message": "Invalid email format."})
    elif len(email) > 255:
        error.append({"field": "email", "message": "Email must be less than 255 characters."})

    return error

def validate_password(password: str) -> bool:
    error=[]
    if not password:
        error.append({"field": "password", "message": "Password is required."})
    elif len(password) < 8:
        error.append({"field": "password", "message": "Password must be at least 8 characters long."})
    elif len(password) > 255:
        error.append({"field": "password", "message": "Password must be less than 255 characters."})
    elif re.search(r'[A-Z]', password) is None:
        error.append({"field": "password", "message": "Password must contain at least one uppercase letter."})
    elif re.search(r'[a-z]', password) is None:
        error.append({"field": "password", "message": "Password must contain at least one lowercase letter."})
    elif re.search(r'[0-9]', password) is None:
        error.append({"field": "password", "message": "Password must contain at least one digit."})
    elif re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is None:
        error.append({"field": "password", "message": "Password must contain at least one special character."})

    return error

def validate_username(username: str) -> bool:
    error=[]
    if not username:
        error.append({"field": "username", "message": "Username is required."})
    elif len(username) < 3:
        error.append({"field": "username", "message": "Username must be at least 3 characters long."})
    elif len(username) > 50:
        error.append({"field": "username", "message": "Username must be less than 50 characters."})
    elif not re.match(r'^[a-zA-Z0-9_]+$', username):
        error.append({"field": "username", "message": "Username can only contain letters, numbers, and underscores."})

    return error

