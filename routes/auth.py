from flask import Blueprint, request, jsonify
from models import User, RefreshToken
from config import Config
from utils.passwords import hash_password, verify_password
from utils.validators import validate_email, validate_password, validate_username
from utils.serializers import user_to_dict, token_to_dict, meta
from utils.tokens import generate_access_token, generate_refresh_token, decode_token
from database import SessionLocal
from datetime import datetime, timedelta
import uuid
import logging
from utils.tokens import generate_access_token, generate_refresh_token, decode_token
authBlueprint = Blueprint('auth', __name__)


def meta():
    return {
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "request_id": str(uuid.uuid4())
    }


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
            "meta":meta(),
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

    except Exception as e:
        session.rollback()
        logging.exception("Error creating user")
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
    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "Invalid JSON payload.",
            "errors": {
                "code": "invalid_json",
                "details": [{"field": None, "message": "Invalid JSON payload."}]
            },
            "meta": meta()
        }), 400

    email = data.get("email")
    password = data.get("password")

    email = email.lower() if email else None

    errors = []

    if not email:
        errors.append({"field": "email", "message": "Email is required."})

    if not password:
        errors.append({"field": "password", "message": "Password is required."})

    if errors:
        return jsonify({
            "success": False,
            "message": "Validation Failed",
            "errors": {
                "code": "validation_error",
                "details": errors
            },
            "meta": meta()
        }), 422

    session = SessionLocal()

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
                "meta": meta()
            }), 401

        if not verify_password(password, user.password_hash):
            return jsonify({
                "success": False,
                "message": "Invalid email or password.",
                "errors": {
                    "code": "invalid_credentials",
                    "details": [{"field": "password", "message": "Invalid email or password."}]
                },
                "meta": meta()
            }), 401

        if not user.is_active:
            return jsonify({
                "success": False,
                "message": "Account is inactive.",
                "errors": {
                    "code": "account_inactive",
                    "details": [{"field": "email", "message": "Account is inactive."}]
                },
                "meta": meta()
            }), 403

        if user.deleted_at is not None:
            return jsonify({
                "success": False,
                "message": "Account has been deleted.",
                "errors": {
                    "code": "account_deleted",
                    "details": [{"field": "email", "message": "Account has been deleted."}]
                },
                "meta": meta()
            }), 410

        access_token = generate_access_token(user.id)
        refresh_token = generate_refresh_token(user.id)

        refresh_token_row = RefreshToken(
            user_id=user.id,
            token=refresh_token,
            expires_at=datetime.utcnow() + timedelta(seconds=Config.JWT_REFRESH_TOKEN_EXPIRES),
            device_info=request.headers.get("User-Agent", "Unknown")
        )

        user.last_login_at = datetime.utcnow()

        session.add(refresh_token_row)
        session.commit()

        return jsonify({
            "success": True,
            "message": "Login successful.",
            "data": {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": Config.JWT_ACCESS_TOKEN_EXPIRES,
                "user": user_to_dict(user)
            },
            "meta": meta()
        }), 200

    except Exception as e:
        print("LOGIN ERROR:", e)
        session.rollback()

        return jsonify({
            "success": False,
            "message": "An error occurred while logging in.",
            "errors": {
                "code": "server_error",
                "details": [{"field": None, "message": "An error occurred while logging in."}]
            },
            "meta": meta()
        }), 500

    finally:
        session.close()
        

@authBlueprint.route('/auth/refresh', methods=['POST'])
def refresh_access_token():
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

    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({
            "success": False,
            "message": "Refresh token is required.",
            "errors": {
                "code": "missing_refresh_token",
                "details": [{"field": "refresh_token", "message": "Refresh token is required."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 400
    decode= decode_token(refresh_token) if refresh_token else None
    if not decode:
        return jsonify({
            "success": False,
            "message": "Invalid refresh token.",
            "errors": {
                "code": "invalid_refresh_token",
                "details": [{"field": "refresh_token", "message": "Invalid refresh token."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 401
    if decode.get('type') != 'refresh':
        return jsonify({
            "success": False,
            "message": "Invalid token type.",
            "errors": {
                "code": "invalid_token_type",
                "details": [{"field": "refresh_token", "message": "Provided token is not a refresh token."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }),401

    session = SessionLocal()
    try:
        stored_token = session.query(RefreshToken).filter_by(token=refresh_token).first()
        
        if not stored_token or stored_token.is_revoked or stored_token.expires_at < datetime.utcnow():
            return jsonify({
                "success": False,
                "message": "Invalid or expired refresh token.",
                "errors": {
                    "code": "invalid_refresh_token",
                    "details": [{"field": "refresh_token", "message": "Invalid or expired refresh token."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 401

        user = session.query(User).filter_by(id=stored_token.user_id).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "User not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [{"field": None, "message": "Invalid or expired refresh token."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 404
        if user.is_active == False or user.deleted_at is not None:
            return jsonify({
                "success": False,
                "message": "User account is not active.",
                "errors": {
                    "code": "account_inactive",
                    "details": [{"field": None, "message": "User account is not active."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 403

        new_access_token = generate_access_token(user.id)

        return jsonify({
            "success": True,
            "message": "Access token refreshed successfully.",
            "data": {
                "access_token": new_access_token,
                "user": user_to_dict(user)
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 200
    except Exception:
        session.rollback()
        return jsonify({
                "success": False,
                "message": "An error occurred while refreshing the access token.",
                "errors": {
                    "code": "database_error",
                    "details": [{"field": None, "message": "An error occurred while refreshing the access token."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 500
    finally:
        session.close()



@authBlueprint.route('/auth/logout', methods=['POST'])
def logout():
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
    token= data.get('refresh_token')
    if not token:
        return jsonify({
            "success": False,
            "message": "Refresh token is required.",
            "errors": {
                "code": "missing_refresh_token",
                "details": [{"field": "refresh_token", "message": "Refresh token is required."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 400
    decode= decode_token(token) if token else None
    if not decode:
        return jsonify({
            "success": False,
            "message": "Invalid refresh token.",
            "errors": {
                "code": "invalid_refresh_token",
                "details": [{"field": "refresh_token", "message": "Invalid refresh token."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 401
    if decode.get('type') != 'refresh':
        return jsonify({
            "success": False,
            "message": "Invalid token type.",
            "errors": {
                "code": "invalid_token_type",
                "details": [{"field": "refresh_token", "message": "Provided token is not a refresh token."}]
            },
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }),401
    session = SessionLocal()
    try:
        stored_token = session.query(RefreshToken).filter_by(token=token).first()
        if not stored_token or stored_token.is_revoked:
            return jsonify({
                "success": False,
                "message": "Invalid refresh token.",
                "errors": {
                    "code": "invalid_refresh_token",
                    "details": [{"field": "refresh_token", "message": "Invalid refresh token."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 401
        if stored_token.expires_at < datetime.utcnow():
            return jsonify({
                "success": False,
                "message": "Refresh token has expired.",
                "errors": {
                    "code": "expired_refresh_token",
                    "details": [{"field": "refresh_token", "message": "Refresh token has expired."}]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + 'Z',
                    "request_id": str(uuid.uuid4())
                },
            }), 401

        stored_token.is_revoked = True
        session.commit()

        return jsonify({
            "success": True,
            "message": "Logged out successfully.",
            "meta": {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "request_id": str(uuid.uuid4())
            },
        }), 200
    except Exception:
        session.rollback()
        return jsonify({
                "success": False,
                "message": "An error occurred while logging out.",
                "errors": {
                    "code": "database_error",
                    "details": [{"field": None, "message": "An error occurred while logging out."}]
                },
                "meta": meta()
            }), 500
    finally:
        session.close()