import jwt
from datetime import datetime, timedelta

def generate_token(user_id, secret_key, algorithm='HS256'):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=24),  # Token expires in 24 hours
        'typ': 'access'
    }
    token = jwt.encode(payload, secret_key, algorithm=algorithm)
    return token

def decode_token(token, secret_key, algorithms=['HS256']):
    try:
        payload = jwt.decode(token, secret_key, algorithms=algorithms)
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    
def refresh_token(token, secret_key, algorithm='HS256'):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[algorithm], options={"verify_exp": False})
        user_id = payload['user_id']
        new_payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)  # New token expires in 24 hours
        }
        new_token = jwt.encode(new_payload, secret_key, algorithm=algorithm)
        return new_token
    except jwt.InvalidTokenError:
        return None  # Invalid token