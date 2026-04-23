# from database import engine

# try:
#     with engine.connect() as conn:
#         print("Connected to DB successfully")
# except Exception as e:
#     print("Connection failed:", e)


from utils.tokens import generate_access_token, decode_token, generate_refresh_token

token = generate_access_token("123")
print(token)
print(type(token))

payload = decode_token(token)
print(payload)

refresh = generate_refresh_token("123")
print(refresh)

payload = decode_token(refresh)
print(payload)