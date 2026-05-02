
from flask import Blueprint, request, session
from flask import jsonify, g
from sqlalchemy import delete

from middleware.auth import require_role, require_auth
from models import User, RefreshToken, reset_token
from utils.serializers import meta, user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid
from utils.validators import validate_username, validate_email, validate_password, validate_role, validate_avatar_url, validate_bio ,validate_name
from utils.passwords import verify_password, hash_password
from models.reset_token import PasswordResetToken
adminBlueprint = Blueprint('admin', __name__)

@adminBlueprint.route('/admin/users', methods=["GET"])
@require_auth
@require_role("admin")
def get_all_users():
    session=SessionLocal()
    try:
        users = session.query(User).filter(User.deleted_at.is_(None)).all()
        data = [user_to_dict(user) for user in users]
        return jsonify({
            "success": True,
            "message": "Users retrieved successfully.",
            "data": data,
            "meta": meta()
        }), 200
    finally:
        session.close()

@adminBlueprint.route('/admin/users/<string:user_id>', methods=["GET"])
@require_auth
@require_role("admin")
def get_user(user_id):
    session=SessionLocal()
    try:
        user = session.query(User).filter(User.id == user_id,User.deleted_at.is_(None)).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "User not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [{"field": None, "message": "User not found."}]
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

@adminBlueprint.route('/admin/users/<string:user_id>', methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_user(user_id):
    session=SessionLocal()
    try:
        user = session.query(User).filter(User.id == user_id, User.deleted_at.is_(None)).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "User not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [{"field": None, "message": "User not found."}]
                },
                "meta": meta()
            }), 404
        
        session.delete(user)
        session.query(RefreshToken).filter_by(user_id=user.id).delete()
        session.query(PasswordResetToken).filter_by(user_id=user.id).delete()
        session.delete(user)
        session.commit()


        return jsonify({
            "success": True,
            "message": "User deleted successfully.", 
            "data": None,
            "meta": meta()
        }), 200
    finally:
        session.close()