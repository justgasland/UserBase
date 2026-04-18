import datetime
from database import Base
from sqlalchemy import Boolean, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship, sessionmaker, relationships, backref
import uuid



class RefreshToken(Base):

    __tablename__ = 'refresh_tokens'

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    token = Column(String(512), unique=True, index=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False, nullable=False)
    device_info = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)