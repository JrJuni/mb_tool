# SQLAlchemy 모델
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    auth_level = Column(Integer, default=0)  # 0: 승인대기, 1-5: 권한레벨
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

class AuditLog(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    actor_user_id = Column(Integer, nullable=False)
    action = Column(String(50), nullable=False)
    table_name = Column(String(50), nullable=False)
    row_id = Column(Integer, nullable=False)
    before_json = Column(JSON)
    after_json = Column(JSON)
    ip = Column(String(45))
    ua = Column(Text)
    created_at = Column(DateTime, default=func.now())