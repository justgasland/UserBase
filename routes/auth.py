from flask import Blueprint, request, jsonify
from models import User
from utils.passwords import hash_password, verify_password
from utils.validators import validate_email, validate_password, validate_username
from utils.serializers import user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid

authBlueprint = Blueprint('auth', __name__)


@authBlueprint.route('/auth/register', methods=['POST'])
def create_user():
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid JSON payload.",
            "errors": {
                "code": "invalid_json",
                "details": [{"field": None, "message": "Invalid JSON payload."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 400

    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    email = email.lower() if email is not None else None

    email_errors = validate_email(email)
    password_errors = validate_password(password)
    username_errors = validate_username(username)

    errors = email_errors + password_errors + username_errors

    if errors:
        return jsonify({
            "success": False,
            "message": "Validation Failed",
            "errors": {
                "code": "validation_error",
                "details": errors
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 422

    session = SessionLocal()

    try:
        existing_user = session.query(User).filter_by(email=email).first()
        if existing_user:
            return jsonify({
                "success": False,
                "message": "Email already exists.",
                "errors": {
                    "code": "email_exists",
                    "details": [{"field": "email", "message": "Email already exists."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 409

        existing_username = session.query(User).filter_by(username=username).first()
        if existing_username:
            return jsonify({
                "success": False,
                "message": "Username already exists.",
                "errors": {
                    "code": "username_exists",
                    "details": [{"field": "username", "message": "Username already exists."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 409

        hashed_password = hash_password(password)
        new_user = User(
            email=email,
            password_hash=hashed_password,
            username=username
        )

        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return jsonify({
            "success": True,
            "message": "User created successfully.",
            "data": user_to_dict(new_user),
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 201

    except Exception:
        session.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred while creating the user.",
            "errors": {
                "code": "database_error",
                "details": [{"field": None, "message": "An error occurred while creating the user."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 500

    finally:
        session.close()

@authBlueprint.route('/auth/login', methods=['POST'])
def login():
    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "message": "Invalid JSON payload.",
                "errors": {
                    "code": "invalid_json",
                    "details": [{"field": None, "message": "Invalid JSON payload."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 400
        email = data.get('email')
        password = data.get('password')

        email = email.lower() if email is not None else None

        session= SessionLocal()
        try:
            user = session.query(User).filter_by(email=email).first()
            if not user:
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password.",
                    "errors": {
                        "code": "invalid_credentials",
                        "details": [{"field": "email", "message": "Invalid email or password."}]
                    },
                    "meta": {
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "request_id": str(uuid.uuid4())
                    },
                }), 401

            if not verify_password(password, user.password_hash):
                return jsonify({
                    "success": False,
                    "message": "Invalid email or password.",
                    "errors": {
                        "code": "invalid_credentials",
                        "details": [{"field": "password", "message": "Invalid email or password."}]
                    },
                    "meta": {
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "request_id": str(uuid.uuid4())
                    },
                }), 401
            

            if not user.is_active:
                return jsonify({
                    "success": False,
                    "message": "Account is inactive. Please contact support.",
                    "errors": {
                        "code": "account_inactive",
                        "details": [{"field": "email", "message": "Account is inactive. Please contact support."}]
                    },
                    "meta": {
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "request_id": str(uuid.uuid4())
                    },
                }), 403

            user.last_login_at = datetime.utcnow()
            session.commit()
        except Exception:
            session.rollback()
            return jsonify({
                    "success": False,
                    "message": "An error occurred while creating the user.",
                    "errors": {
                        "code": "database_error",
                        "details": [{"field": None, "message": "An error occurred while updating the user."}]
                    },
                    "meta": {
                        "timestamp": datetime.utcnow().isoformat() + 'Z',
                        "request_id": str(uuid.uuid4())
                    },
                }), 500
        finally:
            session.close()

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "data": user_to_dict(user),
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 200

