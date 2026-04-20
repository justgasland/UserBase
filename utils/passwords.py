import bcrypt

def hash_password(password: str) -> str:
    hash_password= bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hash_password.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))