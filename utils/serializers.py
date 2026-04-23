import token


def user_to_dict(user):
    return {
        "id": user.id,
        "email": user.email,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }

def token_to_dict(refresh_token):
    return {
        "user_id": refresh_token.user_id,
        "token": refresh_token.token,
        "expires_at": refresh_token.expires_at.isoformat() if refresh_token.expires_at else None,   
        "device_info": refresh_token.device_info,
        "is_revoked": refresh_token.is_revoked,
    }

