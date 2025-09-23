# DB 접근 함수(단계적)
from sqlalchemy.orm import Session
from sqlalchemy import and_
from passlib.context import CryptContext
from datetime import datetime
from typing import Optional, List
from .db_models import User, AuditLog
from .schemas import UserCreate, UserUpdate
from .logging_conf import log_user_creation, log_user_update

# 비밀번호 해싱 컨텍스트
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """비밀번호 검증"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """비밀번호 해싱"""
    return pwd_context.hash(password)

# 사용자 관련 CRUD 함수들
def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
    """ID로 사용자 조회"""
    return db.query(User).filter(User.id == user_id).first()

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """이메일로 사용자 조회"""
    return db.query(User).filter(User.email == email).first()

def get_user_by_username(db: Session, username: str) -> Optional[User]:
    """사용자명으로 사용자 조회"""
    return db.query(User).filter(User.username == username).first()

def get_user_by_email_and_username(db: Session, email: str, username: str) -> Optional[User]:
    """이메일과 사용자명으로 사용자 조회"""
    return db.query(User).filter(and_(User.email == email, User.username == username)).first()

def get_users(db: Session, skip: int = 0, limit: int = 100) -> List[User]:
    """사용자 목록 조회 (페이지네이션)"""
    return db.query(User).offset(skip).limit(limit).all()

def get_users_by_auth_level(db: Session, auth_level: int, skip: int = 0, limit: int = 100) -> List[User]:
    """특정 권한 레벨의 사용자 목록 조회"""
    return db.query(User).filter(User.auth_level == auth_level).offset(skip).limit(limit).all()

def create_user(db: Session, user: UserCreate, ip: Optional[str] = None) -> User:
    """사용자 생성"""
    # 비밀번호 해싱
    hashed_password = get_password_hash(user.password)
    
    # 사용자 객체 생성
    db_user = User(
        email=user.email,
        username=user.username,
        hashed_password=hashed_password,
        auth_level=user.auth_level,
        is_active=user.is_active,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    
    # DB에 저장
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # 로그 기록
    log_user_creation(db_user.id, db_user.email, db_user.auth_level, ip)
    
    return db_user

def update_user(db: Session, user_id: int, user_update: UserUpdate, ip: Optional[str] = None) -> Optional[User]:
    """사용자 정보 수정"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return None
    
    # 변경 전 데이터 저장 (감사 로그용)
    updated_fields = {}
    
    # 필드별 업데이트
    if user_update.email is not None:
        updated_fields['email'] = f"{db_user.email} -> {user_update.email}"
        db_user.email = user_update.email
    
    if user_update.username is not None:
        updated_fields['username'] = f"{db_user.username} -> {user_update.username}"
        db_user.username = user_update.username
    
    if user_update.auth_level is not None:
        updated_fields['auth_level'] = f"{db_user.auth_level} -> {user_update.auth_level}"
        db_user.auth_level = user_update.auth_level
    
    if user_update.is_active is not None:
        updated_fields['is_active'] = f"{db_user.is_active} -> {user_update.is_active}"
        db_user.is_active = user_update.is_active
    
    if user_update.password is not None:
        updated_fields['password'] = "*** -> ***"  # 보안상 비밀번호는 마스킹
        db_user.hashed_password = get_password_hash(user_update.password)
    
    # 수정 시간 업데이트
    db_user.updated_at = datetime.utcnow()
    
    # DB에 저장
    db.commit()
    db.refresh(db_user)
    
    # 로그 기록
    if updated_fields:
        log_user_update(db_user.id, db_user.email, updated_fields, ip)
    
    return db_user

def authenticate_user(db: Session, email: str, password: str) -> Optional[User]:
    """사용자 인증 (이메일/비밀번호 검증)"""
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    if not user.is_active:
        return None
    if user.auth_level == 0:
        return None  # 승인 대기 상태(레벨 0)는 로그인 불가
    return user

def check_password_reset_needed(db: Session, email: str, password: str) -> bool:
    """비밀번호가 0000인지 확인"""
    user = get_user_by_email(db, email)
    if not user:
        return False
    return verify_password("0000", user.hashed_password) and password == "0000"

def reset_password_to_default(db: Session, user_id: int, actor_user_id: int, ip: Optional[str] = None) -> bool:
    """비밀번호를 0000으로 초기화"""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    # 비밀번호를 0000으로 초기화
    user.hashed_password = get_password_hash("0000")
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=actor_user_id,
        action="password_reset",
        table_name="users",
        row_id=user.id,
        after_json={"action": "password_reset_to_0000"},
        ip=ip
    )
    
    return True

def update_password(db: Session, user_id: int, new_password: str, ip: Optional[str] = None) -> bool:
    """사용자 비밀번호 업데이트"""
    user = get_user_by_id(db, user_id)
    if not user:
        return False
    
    user.hashed_password = get_password_hash(new_password)
    user.updated_at = datetime.utcnow()
    
    db.commit()
    
    # 감사 로그 기록
    create_audit_log(
        db=db,
        actor_user_id=user_id,
        action="password_update",
        table_name="users",
        row_id=user.id,
        after_json={"action": "password_updated"},
        ip=ip
    )
    
    return True

def get_users_with_reset_permission(db: Session, user_auth_level: int) -> List[User]:
    """비밀번호 초기화 권한이 있는 사용자 목록 조회 (레벨 3-5, 동급 이상)"""
    return db.query(User).filter(
        and_(
            User.auth_level >= 3,
            User.auth_level >= user_auth_level,
            User.is_active == True
        )
    ).all()

def delete_user(db: Session, user_id: int) -> bool:
    """사용자 삭제 (소프트 삭제)"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return False
    
    # 소프트 삭제: is_active를 False로 설정
    db_user.is_active = False
    db_user.updated_at = datetime.utcnow()
    
    db.commit()
    return True

def hard_delete_user(db: Session, user_id: int) -> bool:
    """사용자 완전 삭제 (레벨 5 이상만 가능)"""
    db_user = get_user_by_id(db, user_id)
    if not db_user:
        return False
    
    db.delete(db_user)
    db.commit()
    return True

# 감사 로그 관련 함수들
def create_audit_log(db: Session, actor_user_id: int, action: str, table_name: str, 
                    row_id: int, before_json: Optional[dict] = None, 
                    after_json: Optional[dict] = None, ip: Optional[str] = None, 
                    user_agent: Optional[str] = None) -> AuditLog:
    """감사 로그 생성"""
    audit_log = AuditLog(
        actor_user_id=actor_user_id,
        action=action,
        table_name=table_name,
        row_id=row_id,
        before_json=before_json,
        after_json=after_json,
        ip=ip,
        ua=user_agent,
        created_at=datetime.utcnow()
    )
    
    db.add(audit_log)
    db.commit()
    db.refresh(audit_log)
    
    return audit_log

def get_audit_logs(db: Session, skip: int = 0, limit: int = 100, 
                  table_name: Optional[str] = None, 
                  actor_user_id: Optional[int] = None) -> List[AuditLog]:
    """감사 로그 조회"""
    query = db.query(AuditLog)
    
    if table_name:
        query = query.filter(AuditLog.table_name == table_name)
    
    if actor_user_id:
        query = query.filter(AuditLog.actor_user_id == actor_user_id)
    
    return query.order_by(AuditLog.created_at.desc()).offset(skip).limit(limit).all()