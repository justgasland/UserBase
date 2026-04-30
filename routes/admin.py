
from flask import Blueprint, request, session
from flask import jsonify, g

from middleware.auth import require_role, require_auth
from models import User, RefreshToken, reset_token
from utils.serializers import meta, user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid
from utils.validators import validate_username, validate_email, validate_password, validate_role, validate_avatar_url, validate_bio ,validate_name
from utils.passwords import verify_password, hash_password

adminBlueprint = Blueprint('admin', __name__)

@adminBlueprint.route('/admin/users', methods=["GET"])
@require_auth
@require_role("admin")
def get_all_users():
    session=SessionLocal()
    try:
        users = session.query(User).all()
        data = [user_to_dict(user) for user in users]
        return jsonify({
            "success": True,
            "message": "Users retrieved successfully.",
            "data": data,
            "meta": meta()
        }), 200
    finally:
        session.close()

@adminBlueprint.route('/admin/users/<string:username>', methods=["GET"])
@require_auth
@require_admin
def get_user_by_username(username):
    session=SessionLocal()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "Username not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [{"field": None, "message": "Username not found."}]
                },
                "meta": meta()
            }), 404
        data = user_to_dict(user)
        return jsonify({
            "success": True,
            "message": "User retrieved successfully.",
            "data": data,
            "meta": meta()
        }), 200
    finally:
        session.close()

@adminBlueprint.route('/admin/users/<string:username>', methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_user_by_username(username):
    session=SessionLocal()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "Username not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [{"field": None, "message": "Username not found."}]
                },
                "meta": meta()
            }), 404
        user.deleted_at = datetime.utcnow()
        session.commit()
        return jsonify({
            "success": True,
            "message": "User deleted successfully.", 
            "data": None,
            "meta": meta()
        }), 200
    finally:
        session.close()