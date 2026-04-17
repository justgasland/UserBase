import datetime
from app import Base
from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, sessionmaker, relationships, backref

from refreshtoken import RefreshToken
from reset_token import PasswordResetToken
import uuid


class User(Base):
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    role=Column(String, nullable=False, default='user', nullable=False)
    is_active=Column(Boolean, nullable=False, default=False)
    is_vefrified=Column(Boolean, nullable=False, default=False)
    avatar_url = Column(String, nullable=True)
    first_name = Column(String, nullable=True)
    last_name = Column(String, nullable=True)
    bio=Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True)
    refresh_token = relationship("RefreshToken", backref="user",lazy='True')
    reset_token = relationship("ResetToken", backref="user",lazy='True')






    