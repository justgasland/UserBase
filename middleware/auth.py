from functools import wraps
from flask import request, jsonify, g
from datetime import datetime
import uuid
from utils.tokens import decode_token
from database import SessionLocal
from models import User
from utils.serializers import meta

ROLE_HIERARCHY = {
    "user": 1,
    "moderator": 2,
    "admin": 3
}


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({
                "success": False,
                "message": "Authorization header is required.",
                "errors": {
                    "code": "missing_authorization_header",
                    "details": [
                        {
                            "field": "Authorization",
                            "message": "Authorization header is required."
                        }
                    ]
                },
                "meta": meta()  
            }), 401

        parts = auth_header.split()

        if len(parts) != 2 or parts[0] != "Bearer":
            return jsonify({
                "success": False,
                "message": "Invalid authorization header format.",
                "errors": {
                    "code": "invalid_authorization_header",
                    "details": [
                        {
                            "field": "Authorization",
                            "message": "Expected format: Bearer <token>."
                        }
                    ]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "request_id": str(uuid.uuid4())
                }
            }), 401

        token = parts[1]

        decode= decode_token(token)
        if not decode:
            return jsonify({
                "success": False,
                "message": "Invalid or expired token.",
                "errors": {
                    "code": "invalid_token",
                    "details": [
                        {
                            "field": "Authorization",
                            "message": "The provided token is invalid or has expired."
                        }
                    ]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "request_id": str(uuid.uuid4())
                }
            }), 401
        if decode.get("type") != "access":
            return jsonify({
                "success": False,
                "message": "Invalid token type.",
                "errors": {
                    "code": "invalid_token_type",
                    "details": [
                        {
                            "field": "Authorization",
                            "message": "Expected an access token."
                        }
                    ]
                },
                "meta": {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "request_id": str(uuid.uuid4())
                }
            }), 401
        session = SessionLocal()
        try:
            user = session.query(User).filter_by(id=decode.get("user_id")).first()
            if not user or not user.is_active or  user.deleted_at is not None:
                return jsonify({
                    "success": False,
                    "message": "User not found or inactive.",
                    "errors": {
                        "code": "User not found or inactive",
                        "details": [
                            {
                                "field": "Authorization",
                                "message": "User not found or inactive."
                            }
                        ]
                    },
                    "meta": meta()
                }), 401
            g.user = user
        except Exception as e:
            return jsonify({
                "success": False,
                "message": "An error occurred while processing the token.",
                "errors": {
                    "code": "token_processing_error",
                    "details": [
                        {
                            "field": "Authorization",
                            "message": str(e)
                        }
                    ]
                },
                "meta": meta()
            }), 500
        finally:
            session.close()


        return func(*args, **kwargs)

    return wrapper


def require_role(required_role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not hasattr(g, "user"):
                return jsonify({
                    "success": False,
                    "message": "Authentication required.",
                    "errors": {
                        "code": "TOKEN_INVALID",
                        "details": [
                            {"field": "Authorization", "message": "Missing or invalid token."}
                        ]
                    },
                    "meta": meta()
                }), 401

            user_role = g.user.role

            if ROLE_HIERARCHY.get(user_role, 0) < ROLE_HIERARCHY.get(required_role, 0):
                return jsonify({
                    "success": False,
                    "message": "Forbidden.",
                    "errors": {
                        "code": "FORBIDDEN",
                        "details": [
                            {"field": "Authorization", "message": "Insufficient permissions."}
                        ]
                    },
                    "meta": meta()
                }), 403

            return func(*args, **kwargs)

        return wrapper
    return decorator