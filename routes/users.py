from flask import Blueprint
from flask import jsonify, g

from middleware.auth import require_auth
from models import User
from utils.serializers import meta, user_to_dict
from database import SessionLocal
from datetime import datetime
import uuid
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