import datetime
from database import Base
from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, sessionmaker, relationships, backref

from models.refresh_token import RefreshToken
from models.reset_token import PasswordResetToken
import uuid


class User(Base):
    __tablename__ = 'users'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    role=Column(String, nullable=False, default='user')
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


    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'role': self.role,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'last_login_at': self.last_login_at.isoformat() if self.last_login_at else None,
            'created_at': self.created_at.isoformat(),
        }

    def to_public_dict(self):
        return {
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'bio': self.bio,
            'avatar_url': self.avatar_url,
            'created_at': self.created_at.isoformat(),
        }






    