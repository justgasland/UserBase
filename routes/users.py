from flask import Blueprint, request, session
from flask import jsonify, g

from middleware.auth import require_auth
from models import User
from utils.serializers import meta, user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid
from utils.validators import validate_username, validate_email, validate_password, validate_role, validate_avatar_url, validate_bio ,validate_name



usersBlueprint = Blueprint('users', __name__)

@usersBlueprint.route("/users/me", methods=["GET"])
@require_auth
def get_me():
    return jsonify({
        "success": True,
        "message": "Profile retrieved successfully.",
        "data": user_to_dict(g.user),
        "meta": meta()
    }), 200

@usersBlueprint.route("/users/me", methods=["PATCH"])
@require_auth
def update_me():
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
    allowed_fields = {
    "username",
    "first_name",
    "last_name",
    "bio",
    "avatar_url"
    }
    for field in data.keys():
        if field not in allowed_fields:
            return jsonify({
                "success": False,
                "message": "Invalid field in payload.",
                "errors": {
                    "code": "invalid_field",
                    "details": [{"field": field, "message": f"Field '{field}' is not allowed."}]
                },
                "meta": meta()
            }), 400
    username = data.get("username")
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    bio = data.get("bio")
    avatar_url = data.get("avatar_url")


    errors=[]
    if username is not None:
        username_error = validate_username(username)
        if username_error:
            errors.extend(username_error)
    if first_name is not None:
        first_name_error = validate_name(first_name, "first_name")
        if first_name_error:
            errors.extend(first_name_error)
    if last_name is not None:
        last_name_error = validate_name(last_name, "last_name")
        if last_name_error:
            errors.extend(last_name_error)
    if bio is not None:
        bio_error = validate_bio(bio)
        if bio_error:
            errors.extend(bio_error)
    if avatar_url is not None:
        avatar_url_error = validate_avatar_url(avatar_url)
        if avatar_url_error:
            errors.extend(avatar_url_error)
    if errors:
        return jsonify({
            "success": False,
            "message": "Validation errors.",
            "errors": {
                "code": "validation_error",
                "details": errors
            },
            "meta": meta()
        }), 400
    

    session = SessionLocal()
    try:

        user = session.query(User).filter_by(id=g.user.id).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "User not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [
                        {
                            "field": None,
                            "message": "User not found."
                        }
                    ]
                },
                "meta": meta()
                }), 404
                    
            
        if username is not None and username != user.username:
            existing_user = session.query(User).filter_by(username=username).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({
                    "success": False,
                    "message": "Username already taken.",
                    "errors": {
                        "code": "username_taken",
                        "details": [
                            {
                                "field": "username",
                                "message": "Username is already taken by another user."
                            }
                        ]
                    },
                    "meta": meta()
                }), 400
            user.username = username


        if first_name is not None:
            user.first_name = first_name
        if last_name is not None:
            user.last_name = last_name
        if bio is not None:
            user.bio = bio
        if avatar_url is not None:
            user.avatar_url = avatar_url
        session.commit()
        return jsonify({
            "success": True,
            "message": "Profile updated successfully.",
            "data": user_to_dict(user),
            "meta": meta()
        }), 200
    

    except Exception as e:
        # print("PROFILE UPDATE ERROR:", e)
        session.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred while updating the profile.",
            "errors": {
                "code": "profile_update_error",
                "details": [
                    {
                        "field": None,
                        "message": "An unexpected error occurred while updating the profile. Please try again later."
                    }
                ]
            },
            "meta": meta()
        }), 500
    
    finally:        
        session.close()


@usersBlueprint.route("/users/me", methods=["DELETE"])
@require_auth
def delete_me():
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(id=g.user.id).first()
        if not user:
            return jsonify({
                "success": False,
                "message": "User not found.",
                "errors": {
                    "code": "user_not_found",
                    "details": [
                        {
                            "field": None,
                            "message": "User not found."
                        }
                    ]
                },
                "meta": meta()
            }), 404
        
        user.deleted_at = datetime.utcnow()
        # user.acces
        session.commit()
        return jsonify({
            "success": True,
            "message": "Account deleted successfully.",
            "meta": meta()
        }), 200

    except Exception as e:
        session.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred while deleting the account.",
            "errors": {
                "code": "account_deletion_error",
                "details": [
                    {
                        "field": None,
                        "message": "An unexpected error occurred while deleting the account. Please try again later."
                    }
                ]
            },
            "meta": meta()
        }), 500
    finally:
        session.close()
