
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

def validate_role(role: str) -> bool:
    error=[]
    valid_roles = ['user', 'admin']
    if not role:
        error.append({"field": "role", "message": "Role is required."})
    elif role not in valid_roles:
        error.append({"field": "role", "message": f"Role must be one of the following: {', '.join(valid_roles)}."})

    return error

def validate_avatar_url(avatar_url: str) -> bool:
    error=[]
    if not isinstance(avatar_url, str):
        error.append({"field": "avatar_url", "message": "Avatar URL must be a string."})
    elif avatar_url and len(avatar_url) > 500:
        error.append({"field": "avatar_url", "message": "Avatar URL must be less than 500 characters."})
    elif avatar_url and not re.match(r'^(https?://)?(www\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/[\w\-._~:/?#[\]@!$&\'()*+,;=]*)?$', avatar_url):
        error.append({"field": "avatar_url", "message": "Invalid URL format for avatar."})

    return error


def validate_bio(bio: str) -> bool:
    error=[]
    if not isinstance(bio, str):
        error.append({"field": "bio", "message": "Bio must be a string."})
    elif bio and len(bio) > 1000:
        error.append({"field": "bio", "message": "Bio must be less than 1000 characters."})

    return error

def validate_name(name: str, field_name: str) -> bool:
    error=[]
    if not isinstance(name, str):
        error.append({"field": field_name, "message": f"{field_name.replace('_', ' ').title()} must be a string."})
    elif name and len(name) > 100:
        error.append({"field": field_name, "message": f"{field_name.replace('_', ' ').title()} must be less than 100 characters."})

    return error

