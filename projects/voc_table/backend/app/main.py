# FastAPI 엔트리 포인트
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional
import jwt
import os

from . import crud, schemas
from .db import get_db
from .logging_conf import (
    log_login_success, log_login_failure, log_logout, 
    log_auth_failure, log_permission_denied
)

# FastAPI 앱 초기화
app = FastAPI(
    title="VOC Table API",
    description="AI VOC 시스템 API",
    version="1.0.0"
)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501"],  # Streamlit 프론트엔드
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT 설정
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MIN", "30"))

# OAuth2 스키마
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# JWT 토큰 생성
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """JWT 액세스 토큰 생성"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 현재 사용자 인증
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """현재 로그인한 사용자 정보 조회"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    
    user = crud.get_user_by_id(db, user_id=user_id)
    if user is None:
        raise credentials_exception
    
    return user

# 권한 검증 의존성
def require_auth_level(required_level: int):
    """권한 레벨 검증 데코레이터"""
    def auth_dependency(current_user: schemas.User = Depends(get_current_user)):
        if current_user.auth_level < required_level:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"auth_level_{required_level}", required_level, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required level: {required_level}, Current level: {current_user.auth_level}"
            )
        return current_user
    return auth_dependency

# 클라이언트 IP 추출
def get_client_ip(request: Request) -> str:
    """클라이언트 IP 주소 추출"""
    x_forwarded_for = request.headers.get("X-Forwarded-For")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()
    return request.client.host

# 헬스체크
@app.get("/health")
async def health_check():
    """헬스체크 엔드포인트"""
    return {"status": "OK", "timestamp": datetime.utcnow()}

# =============================================================================
# 인증 관련 엔드포인트
# =============================================================================

@app.post("/auth/login", response_model=schemas.Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    """사용자 로그인"""
    # 클라이언트 정보 추출
    ip = get_client_ip(request) if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    
    # 사용자 인증
    user = crud.authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        log_login_failure(form_data.username, "Invalid credentials", ip, user_agent)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # JWT 토큰 생성
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user.id)}, expires_delta=access_token_expires
    )
    
    # 로그인 성공 로그
    log_login_success(user.id, user.email, ip, user_agent)
    
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/auth/me", response_model=schemas.User)
async def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    """현재 로그인한 사용자 정보 조회"""
    return current_user

@app.post("/auth/logout")
async def logout(
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 로그아웃"""
    ip = get_client_ip(request) if request else None
    
    # 로그아웃 로그
    log_logout(current_user.id, current_user.email, ip)
    
    return {"message": "Successfully logged out"}

# =============================================================================
# 사용자 관리 엔드포인트
# =============================================================================

@app.get("/users/", response_model=list[schemas.User])
async def read_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))  # 레벨 4 이상만 조회 가능
):
    """사용자 목록 조회 (관리자만)"""
    users = crud.get_users(db, skip=skip, limit=limit)
    return users

@app.post("/users/register", response_model=schemas.User)
async def register_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    request: Request = None
):
    """사용자 회원가입 (누구나 가능, 레벨 0으로 승인 대기)"""
    # 이메일 중복 확인
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # 회원가입 시에는 항상 레벨 0으로 설정 (승인 대기)
    user.auth_level = 0
    
    ip = get_client_ip(request) if request else None
    return crud.create_user(db=db, user=user, ip=ip)

@app.post("/users/", response_model=schemas.User)
async def create_user(
    user: schemas.UserCreate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """관리자 사용자 생성 (레벨 3 이상)"""
    # 레벨 3 이상만 사용자 생성 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"create_user", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to create users"
        )
    
    # 이메일 중복 확인
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )
    
    # 레벨 5는 생성 불가 (대표님 고정)
    if user.auth_level == 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"create_user_level_5", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5 users cannot be created (CEO level is fixed)"
        )
    
    # 권한별 생성 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 생성 가능
        if user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"create_user_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only create users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 생성 가능
        if user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"create_user_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only create users with level 0-4"
            )
    
    ip = get_client_ip(request) if request else None
    return crud.create_user(db=db, user=user, ip=ip)

@app.get("/users/{user_id}", response_model=schemas.User)
async def read_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """사용자 정보 조회"""
    db_user = crud.get_user_by_id(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인 정보이거나 권한에 따라 조회 가능
    if current_user.id != user_id:
        if current_user.auth_level < 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"read_user_{user_id}", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3+ required to view other users"
            )
        
        # 권한별 조회 가능 레벨 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3만 조회 가능
            if db_user.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"read_user_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only view users with level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 조회 가능 (레벨 5는 조회 불가)
            if db_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"read_user_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only view users with level 0-4"
                )
    
    return db_user

@app.patch("/users/{user_id}", response_model=schemas.User)
async def update_user(
    user_id: int,
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 정보 수정"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")
    
    # 본인 정보이거나 권한에 따라 수정 가능
    if current_user.id != user_id:
        if current_user.auth_level < 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"update_user_{user_id}", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3+ required to modify other users"
            )
        
        # 권한별 수정 가능 레벨 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3만 수정 가능
            if target_user.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"update_user_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only modify users with level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 수정 가능 (레벨 5는 수정 불가)
            if target_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"update_user_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only modify users with level 0-4"
                )
    
    # 권한 레벨 변경 권한 검증
    if user_update.auth_level is not None:
        # 레벨 5는 변경 불가 (대표님 고정)
        if user_update.auth_level == 5:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"change_auth_level_{user_id}_to_5", 5, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 5 cannot be set (CEO level is fixed)"
            )
        
        # 권한별 레벨 변경 제한
        if current_user.auth_level == 3:
            # 레벨 3: 레벨 0-3까지만 설정 가능
            if user_update.auth_level > 3:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"change_auth_level_{user_id}_level_3_limit", 3, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 3 users can only set auth level 0-3"
                )
        elif current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4까지만 설정 가능
            if user_update.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"change_auth_level_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only set auth level 0-4"
                )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 비활성화 (is_active = False)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인은 비활성화 불가
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot deactivate your own account"
        )
    
    # 레벨 3 이상만 사용자 비활성화 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"deactivate_user_{user_id}", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to deactivate users"
        )
    
    # 권한별 비활성화 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 비활성화 가능
        if target_user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"deactivate_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only deactivate users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 비활성화 가능 (레벨 5는 비활성화 불가)
        if target_user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"deactivate_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only deactivate users with level 0-4"
            )
    
    # 사용자 비활성화
    user_update = schemas.UserUpdate(is_active=False)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User deactivated successfully"}

@app.patch("/users/{user_id}/activate")
async def activate_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 활성화 (is_active = True)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 레벨 3 이상만 사용자 활성화 가능
    if current_user.auth_level < 3:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"activate_user_{user_id}", 3, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 3+ required to activate users"
        )
    
    # 권한별 활성화 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 0-3만 활성화 가능
        if target_user.auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"activate_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only activate users with level 0-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 0-4만 활성화 가능 (레벨 5는 활성화 불가)
        if target_user.auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"activate_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only activate users with level 0-4"
            )
    
    # 사용자 활성화
    user_update = schemas.UserUpdate(is_active=True)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User activated successfully"}

@app.patch("/users/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """사용자 비밀번호 초기화 (0000으로 설정)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 본인 비밀번호 초기화 또는 레벨 4 이상만 다른 사용자 비밀번호 초기화 가능
    if current_user.id != user_id:
        if current_user.auth_level < 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"reset_password_{user_id}", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4+ required to reset other users' passwords"
            )
        
        # 권한별 비밀번호 초기화 가능 레벨 제한
        if current_user.auth_level == 4:
            # 레벨 4: 레벨 0-4만 비밀번호 초기화 가능 (레벨 5는 불가)
            if target_user.auth_level > 4:
                log_permission_denied(
                    current_user.id, current_user.email, 
                    f"reset_password_{user_id}_level_4_limit", 4, current_user.auth_level
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Level 4 users can only reset passwords for users with level 0-4"
                )
    
    # 비밀번호 초기화 (0000으로 설정)
    user_update = schemas.UserUpdate(password="0000")
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 로그
    from .logging_conf import log_user_update
    log_user_update(
        current_user.id, current_user.email, 
        {"password_reset": f"User {target_user.email} password reset to 0000"}, ip
    )
    
    return {"message": "Password reset successfully to 0000"}

@app.patch("/users/me", response_model=schemas.User)
async def update_my_profile(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """본인 개인정보 수정 (모든 사용자 가능)"""
    # 본인 정보만 수정 가능
    # auth_level은 변경 불가 (보안상)
    if user_update.auth_level is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own auth level"
        )
    
    # is_active는 변경 불가 (보안상)
    if user_update.is_active is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot change your own active status"
        )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=current_user.id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/reset-password-admin")
async def reset_user_password_admin(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """HR 관리자용 비밀번호 초기화 (레벨 5 전용)"""
    # HR 관리자 계정만 사용 가능 (레벨 5 + 특별한 이메일 패턴)
    if current_user.auth_level != 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"admin_reset_password_{user_id}", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR admin accounts can use this endpoint"
        )
    
    # HR 관리자 계정 확인 (admin으로 시작하는 이메일)
    if not current_user.email.startswith("admin"):
        log_permission_denied(
            current_user.id, current_user.email, 
            f"admin_reset_password_{user_id}_not_admin", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin accounts can use this endpoint"
        )
    
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 (0000으로 설정)
    user_update = schemas.UserUpdate(password="0000")
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 비밀번호 초기화 로그
    from .logging_conf import log_user_update
    log_user_update(
        current_user.id, current_user.email, 
        {"admin_password_reset": f"HR Admin reset password for user {target_user.email} to 0000"}, ip
    )
    
    return {"message": f"Password reset successfully to 0000 for user {target_user.email}"}

@app.patch("/users/me/admin-profile")
async def update_admin_profile(
    user_update: schemas.UserUpdate,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user),
    request: Request = None
):
    """HR 관리자용 본인 정보 수정 (비밀번호만 변경 가능)"""
    # HR 관리자 계정만 사용 가능 (레벨 5 + 특별한 이메일 패턴)
    if current_user.auth_level != 5:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only HR admin accounts can use this endpoint"
        )
    
    # HR 관리자 계정 확인 (admin으로 시작하는 이메일)
    if not current_user.email.startswith("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admin accounts can use this endpoint"
        )
    
    # HR 관리자는 비밀번호만 변경 가능
    if user_update.email is not None or user_update.name is not None or user_update.auth_level is not None or user_update.is_active is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="HR admin can only change password"
        )
    
    # 비밀번호만 변경 가능
    if user_update.password is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only password can be updated for HR admin"
        )
    
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=current_user.id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.delete("/users/{user_id}/hard")
async def hard_delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
):
    """사용자 완전 삭제 (레벨 5 이상만)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 레벨 5 이상만 완전 삭제 가능
    if current_user.auth_level < 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"hard_delete_user_{user_id}", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5+ required for permanent deletion"
        )
    
    # 본인은 삭제 불가
    if current_user.id == user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot permanently delete your own account"
        )
    
    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User permanently deleted"}

@app.patch("/users/{user_id}/approve", response_model=schemas.User)
async def approve_user(
    user_id: int,
    new_auth_level: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),  # 레벨 3 이상만 승인 가능
    request: Request = None
):
    """사용자 승인 (레벨 0 → 지정된 레벨로 승인)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 승인 대기 상태(레벨 0)가 아니면 승인 불가
    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not in pending approval status"
        )
    
    # 레벨 5는 승인 불가 (대표님 고정)
    if new_auth_level == 5:
        log_permission_denied(
            current_user.id, current_user.email, 
            f"approve_user_{user_id}_to_5", 5, current_user.auth_level
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Level 5 cannot be approved (CEO level is fixed)"
        )
    
    # 권한별 승인 가능 레벨 제한
    if current_user.auth_level == 3:
        # 레벨 3: 레벨 1-3까지만 승인 가능
        if new_auth_level > 3:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"approve_user_{user_id}_level_3_limit", 3, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 3 users can only approve users with level 1-3"
            )
    elif current_user.auth_level == 4:
        # 레벨 4: 레벨 1-4까지만 승인 가능
        if new_auth_level > 4:
            log_permission_denied(
                current_user.id, current_user.email, 
                f"approve_user_{user_id}_level_4_limit", 4, current_user.auth_level
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Level 4 users can only approve users with level 1-4"
            )
    
    # 사용자 승인 (레벨 변경)
    user_update = schemas.UserUpdate(auth_level=new_auth_level)
    ip = get_client_ip(request) if request else None
    db_user = crud.update_user(db=db, user_id=user_id, user_update=user_update, ip=ip)
    
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    return db_user

@app.patch("/users/{user_id}/reject")
async def reject_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3)),  # 레벨 3 이상만 거부 가능
    request: Request = None
):
    """사용자 가입 거부 (레벨 0 사용자 삭제)"""
    # 대상 사용자 정보 조회
    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # 승인 대기 상태(레벨 0)가 아니면 거부 불가
    if target_user.auth_level != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is not in pending approval status"
        )
    
    # 사용자 완전 삭제 (가입 거부)
    success = crud.hard_delete_user(db=db, user_id=user_id)
    if not success:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User registration rejected and deleted"}

@app.post("/admin/setup-default-hr")
async def setup_default_hr_admin(
    db: Session = Depends(get_db),
    request: Request = None
):
    """기본 HR 관리자 계정 설정 (admin@mobilint.com / 0000)"""
    # 기존 HR 관리자 계정이 있는지 확인
    existing_hr_admins = crud.get_users_by_auth_level(db, auth_level=5)
    admin_emails = [user.email for user in existing_hr_admins if user.email.startswith("admin")]
    
    if admin_emails:
        return {
            "message": "HR admin accounts already exist",
            "existing_admins": admin_emails,
            "note": "Use existing admin accounts or contact system administrator"
        }
    
    # 기본 HR 관리자 계정 생성
    hr_admin_data = schemas.UserCreate(
        email="admin@mobilint.com",
        name="HR Admin",
        password="0000",
        auth_level=5,
        is_active=True
    )
    
    ip = get_client_ip(request) if request else None
    hr_admin = crud.create_user(db=db, user=hr_admin_data, ip=ip)
    
    return {
        "message": "Default HR admin account created successfully",
        "credentials": {
            "email": "admin@mobilint.com",
            "password": "0000",
            "note": "Please change password on first login"
        },
        "user": hr_admin
    }

@app.get("/users/pending", response_model=list[schemas.User])
async def get_pending_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(3))  # 레벨 3 이상만 조회 가능
):
    """승인 대기 사용자 목록 조회 (레벨 0 사용자들)"""
    pending_users = crud.get_users_by_auth_level(db, auth_level=0, skip=skip, limit=limit)
    return pending_users

# =============================================================================
# 감사 로그 엔드포인트
# =============================================================================

@app.get("/audit-logs/", response_model=list[schemas.AuditLog])
async def read_audit_logs(
    skip: int = 0,
    limit: int = 100,
    table_name: Optional[str] = None,
    actor_user_id: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: schemas.User = Depends(require_auth_level(4))  # 레벨 4 이상만 조회 가능
):
    """감사 로그 조회 (관리자만)"""
    audit_logs = crud.get_audit_logs(
        db, skip=skip, limit=limit, 
        table_name=table_name, actor_user_id=actor_user_id
    )
    return audit_logs