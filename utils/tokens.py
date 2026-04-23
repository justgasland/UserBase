# import pyjwt as jwt
import jwt as jwt
from datetime import datetime, timedelta
from config import Config

# from jwt import InvalidTokenError, ExpiredSignatureError


def generate_access_token(user_id: str):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(seconds=Config.JWT_ACCESS_TOKEN_EXPIRES),  # Token expires in 24 hours
        'type': 'access'
    }
    token = jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')
    return token


    
def generate_refresh_token(user_id: str):
    try:
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(seconds=Config.JWT_REFRESH_TOKEN_EXPIRES), 
        }
        return jwt.encode(payload, Config.JWT_SECRET_KEY, algorithm='HS256')
    except jwt.InvalidTokenError:
        return None  # Invalid token
    

def decode_token(token: str) -> dict | None:
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token