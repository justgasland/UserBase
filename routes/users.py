from flask import Blueprint, request, session
from flask import jsonify, g

from middleware.auth import require_auth
from models import User, RefreshToken, reset_token
from utils.serializers import meta, user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid
from utils.validators import validate_username, validate_email, validate_password, validate_role, validate_avatar_url, validate_bio ,validate_name
from utils.passwords import verify_password, hash_password

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
        session.query(RefreshToken).filter_by(user_id=user.id,is_revoked=False).update({"is_revoked": True})
        
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



@usersBlueprint.route("/users/me/change-password", methods=["POST"])
@require_auth
def change_password():
    data= request.get_json()
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
    
    current_password=data.get("current_password")
    new_password=data.get("new_password")
    

    if current_password is None:
        return jsonify({
            "success": False,
            "message": "Current password is required.",
            "errors": {
                "code": "Validation Error",
                "details": [{"field": "current_password", "message": "Current password is required."}]
            },
            "meta": meta()
        }), 422
    if new_password is None:
        return jsonify({
            "success": False,
            "message": "New Password is Required.",
            "errors": {
                "code": "Validation Error",
                "details": [{"field": "new_password", "message": "New password is required."}]
            },
            "meta": meta()
        }), 422
    else:
        password_error = validate_password(new_password)
        if password_error:
            return jsonify({
                "success": False,
                "message": "Validation Error.",
                "errors": {
                    "code": "validation_error",
                    "details": password_error
                },
                "meta": meta()
            }), 422
        
    session = SessionLocal()
    try:
        user = session.query(User).filter_by(id=g.user.id).first()
        if user is None:
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
        
        verify_error=verify_password(current_password, user.password_hash)
        if not verify_error:
            return jsonify({
                "success": False,
                "message": "Current password is incorrect.",
                "errors": {
                    "code": "incorrect_password",
                    "details": [
                        {
                            "field": "current_password",
                            "message": "Current password is incorrect."
                        }
                    ]
                },
                "meta": meta()
            }), 401
        
        hashed_password = hash_password(new_password)
        user.password_hash = hashed_password

        session.query(RefreshToken).filter_by(user_id=user.id,is_revoked=False).update({"is_revoked": True})


        session.commit()

        return jsonify({
            "success": True,
            "message": "Password changed successfully.",
            "data": 'null',
            "meta": meta()
        }), 200
    
    except Exception as e:
        session.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred while changing the password.",
            "errors": {
                "code": "account_deletion_error",
                "details": [
                    {
                        "field": None,
                        "message": "An unexpected error occurred while changing the password. Please try again later."
                    }
                ]
            },
            "meta": meta()
        }), 500
    finally:
        session.close()

        


@usersBlueprint.route("/users/me/sessions", methods=["GET"])
@require_auth
def user_session():
    session=SessionLocal()
    try:
        refresh_tokens = session.query(RefreshToken).filter_by(
            user_id=g.user.id,
            is_revoked=False
        ).all()
        if not refresh_tokens:
            return jsonify({
                "success": False,
                "message": "No active sessions found.",
                "data": None,
                "meta": meta()
            }), 404
        
        return jsonify({
            "success":True,
            "message": "Active sessions retrieved successfully",
            "data": [
                {
                    "id": refresh_token.id,
                    "device_info": refresh_token.device_info,
                    "created_at": refresh_token.created_at.isoformat() if refresh_token.created_at else None,
                    "expires_at": refresh_token.expires_at.isoformat() if refresh_token.expires_at else None
                }
                for refresh_token in refresh_tokens
            ],
            "meta": meta()

        }), 200
    except Exception:
        return jsonify({
            "success": False,
            "message": "An error occurred while retrieving sessions.",
            "errors": {
                "code": "sessions_fetch_error",
                "details": [{"field": None, "message": "An unexpected error occurred."}]
                },
                "meta": meta()
            }), 500

    finally:
        session.close()


@usersBlueprint.route('/users/me/sessions/<string:id>', methods=["DELETE"])
@require_auth
def delete_session(id):
    session = SessionLocal()
    try:
        refresh_token = session.query(RefreshToken).filter_by(id=id, user_id=g.user.id).first()
        if not refresh_token:
            return jsonify({
                "success": False,
                "message": "Session not found.",
                "errors": {
                    "code": "session_not_found",
                    "details": [{"field": None, "message": "Session not found."}]
                },
                "meta": meta()
            }), 404
        if refresh_token.is_revoked:
            return jsonify({
                "success": False,
                "message": "Session is already revoked.",
                "errors": {
                    "code": "session_already_revoked",
                    "details": [{"field": None, "message": "Session is already revoked."}]
                },
                "meta": meta()
            }), 400
        
        refresh_token.is_revoked = True
        session.commit()

        return jsonify({
            "success": True,
            "message": "Session revoked successfully.",
            "data": None,
            "meta": meta()
        }), 200

    except Exception:
        session.rollback()
        return jsonify({
            "success": False,
            "message": "An error occurred while revoking the session.",
            "errors": {
                "code": "session_revoke_error",
                "details": [{"field": None, "message": "An unexpected error occurred."}]
            },
            "meta": meta()
        }), 500
    finally:
        session.close()


@usersBlueprint.route('/users/<string:username>', methods=["GET"])
def get_username(username):
    session=SessionLocal()
    try:
        user=session.query(User).filter_by(username=username).first()
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
        data={
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "bio": user.bio,
            "avatar_url": user.avatar_url
        }

        return jsonify({
            "success": True,
            "message": "User retrieved successfully",
            "data": data,
            "meta": meta()
        }), 200
    finally:
        session.close()

    




    

        

    




