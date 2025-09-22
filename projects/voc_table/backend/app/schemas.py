# 필요한 라이브러리 import
from typing import Optional
from datetime import datetime, date
from pydantic import BaseModel, EmailStr


# =============================================================================
# 사용자(User) 관련 스키마
# =============================================================================

class UserBase(BaseModel):
    """사용자 기본 정보 스키마"""
    email: EmailStr  # 이메일 주소 (유효성 검증 포함)
    name: str  # 사용자 이름
    auth_level: int = 0  # 권한 레벨 (기본값: 0)
    is_active: bool = True  # 계정 활성화 상태 (기본값: True)


class UserCreate(UserBase):
    """사용자 생성 시 사용하는 스키마"""
    password: str  # 비밀번호


class UserUpdate(BaseModel):
    """사용자 정보 수정 시 사용하는 스키마 (이메일은 필수, 나머지는 선택적)"""
    email: EmailStr  # 이메일 (필수 - 회사 내부 시스템이므로)
    name: Optional[str] = None  # 이름 (선택적)
    auth_level: Optional[int] = None  # 권한 레벨 (선택적)
    is_active: Optional[bool] = None  # 활성화 상태 (선택적)
    password: Optional[str] = None  # 비밀번호 (선택적)


class User(UserBase):
    """데이터베이스에서 조회된 사용자 정보 스키마"""
    id: int  # 사용자 고유 ID
    created_at: datetime  # 생성 시간
    updated_at: datetime  # 수정 시간

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# 회사(Company) 관련 스키마
# =============================================================================

class CompanyBase(BaseModel):
    """회사 기본 정보 스키마"""
    name: str  # 회사명
    domain: Optional[str] = None  # 도메인 (선택적)
    revenue: Optional[str] = None  # 매출 (선택적)
    employee: Optional[int] = None  # 직원 수 (선택적)
    nation: Optional[str] = None  # 국가 (선택적)


class CompanyCreate(CompanyBase):
    """회사 생성 시 사용하는 스키마"""
    pass  # CompanyBase의 모든 필드를 상속


class CompanyUpdate(BaseModel):
    """회사 정보 수정 시 사용하는 스키마 (모든 필드 선택적)"""
    name: Optional[str] = None  # 회사명 (선택적)
    domain: Optional[str] = None  # 도메인 (선택적)
    revenue: Optional[str] = None  # 매출 (선택적)
    employee: Optional[int] = None  # 직원 수 (선택적)
    nation: Optional[str] = None  # 국가 (선택적)


class Company(CompanyBase):
    """데이터베이스에서 조회된 회사 정보 스키마"""
    id: int  # 회사 고유 ID
    created_at: datetime  # 생성 시간
    updated_at: datetime  # 수정 시간

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# 연락처(Contact) 관련 스키마
# =============================================================================

class ContactBase(BaseModel):
    """연락처 기본 정보 스키마"""
    name: str  # 연락처 이름
    title: Optional[str] = None  # 직책 (선택적)
    email: Optional[EmailStr] = None  # 이메일 (선택적)
    phone: Optional[str] = None  # 전화번호 (선택적)
    note: Optional[str] = None  # 메모 (선택적)


class ContactCreate(ContactBase):
    """연락처 생성 시 사용하는 스키마"""
    company_id: int  # 소속 회사 ID (필수)


class ContactUpdate(BaseModel):
    """연락처 정보 수정 시 사용하는 스키마 (모든 필드 선택적)"""
    name: Optional[str] = None  # 이름 (선택적)
    title: Optional[str] = None  # 직책 (선택적)
    email: Optional[EmailStr] = None  # 이메일 (선택적)
    phone: Optional[str] = None  # 전화번호 (선택적)
    note: Optional[str] = None  # 메모 (선택적)
    company_id: Optional[int] = None  # 소속 회사 ID (선택적)


class Contact(ContactBase):
    """데이터베이스에서 조회된 연락처 정보 스키마"""
    id: int  # 연락처 고유 ID
    company_id: int  # 소속 회사 ID
    created_at: datetime  # 생성 시간
    updated_at: datetime  # 수정 시간

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# 프로젝트(Project) 관련 스키마
# =============================================================================

class ProjectBase(BaseModel):
    """프로젝트 기본 정보 스키마"""
    name: str  # 프로젝트명
    field: Optional[str] = None  # 분야 (선택적)
    target_app: Optional[str] = None  # 대상 애플리케이션 (선택적)
    ai_model: Optional[str] = None  # AI 모델 (선택적)
    perf: Optional[str] = None  # 성능 (선택적)
    power: Optional[str] = None  # 전력 (선택적)
    size: Optional[str] = None  # 크기 (선택적)
    price: Optional[str] = None  # 가격 (선택적)
    requirements: Optional[str] = None  # 요구사항 (선택적)
    competitors: Optional[str] = None  # 경쟁사 (선택적)
    result: Optional[str] = None  # 결과 (선택적)
    why: Optional[str] = None  # 이유 (선택적)


class ProjectCreate(ProjectBase):
    """프로젝트 생성 시 사용하는 스키마"""
    company_id: int  # 소속 회사 ID (필수)


class ProjectUpdate(BaseModel):
    """프로젝트 정보 수정 시 사용하는 스키마 (모든 필드 선택적)"""
    name: Optional[str] = None  # 프로젝트명 (선택적)
    company_id: Optional[int] = None  # 소속 회사 ID (선택적)
    field: Optional[str] = None  # 분야 (선택적)
    target_app: Optional[str] = None  # 대상 애플리케이션 (선택적)
    ai_model: Optional[str] = None  # AI 모델 (선택적)
    perf: Optional[str] = None  # 성능 (선택적)
    power: Optional[str] = None  # 전력 (선택적)
    size: Optional[str] = None  # 크기 (선택적)
    price: Optional[str] = None  # 가격 (선택적)
    requirements: Optional[str] = None  # 요구사항 (선택적)
    competitors: Optional[str] = None  # 경쟁사 (선택적)
    result: Optional[str] = None  # 결과 (선택적)
    why: Optional[str] = None  # 이유 (선택적)


class Project(ProjectBase):
    """데이터베이스에서 조회된 프로젝트 정보 스키마"""
    id: int  # 프로젝트 고유 ID
    company_id: int  # 소속 회사 ID
    created_at: datetime  # 생성 시간
    updated_at: datetime  # 수정 시간

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# VOC(Voice of Customer) 관련 스키마
# =============================================================================

class VOCBase(BaseModel):
    """VOC 기본 정보 스키마"""
    date: date  # VOC 발생 날짜
    content: str  # VOC 내용
    action_item: Optional[str] = None  # 액션 아이템 (선택적)
    due_date: Optional[date] = None  # 마감일 (선택적)
    status: str = "pending"  # 상태 (기본값: pending)
    priority: str = "medium"  # 우선순위 (기본값: medium)


class VOCCreate(VOCBase):
    """VOC 생성 시 사용하는 스키마"""
    company_id: int  # 소속 회사 ID (필수)
    contact_id: Optional[int] = None  # 연락처 ID (선택적)
    project_id: Optional[int] = None  # 프로젝트 ID (선택적)


class VOCUpdate(BaseModel):
    """VOC 정보 수정 시 사용하는 스키마 (모든 필드 선택적)"""
    date: Optional[date] = None  # VOC 발생 날짜 (선택적)
    company_id: Optional[int] = None  # 소속 회사 ID (선택적)
    contact_id: Optional[int] = None  # 연락처 ID (선택적)
    project_id: Optional[int] = None  # 프로젝트 ID (선택적)
    content: Optional[str] = None  # VOC 내용 (선택적)
    action_item: Optional[str] = None  # 액션 아이템 (선택적)
    due_date: Optional[date] = None  # 마감일 (선택적)
    status: Optional[str] = None  # 상태 (선택적)
    priority: Optional[str] = None  # 우선순위 (선택적)


class VOC(VOCBase):
    """데이터베이스에서 조회된 VOC 정보 스키마"""
    id: int  # VOC 고유 ID
    company_id: int  # 소속 회사 ID
    contact_id: Optional[int] = None  # 연락처 ID (선택적)
    project_id: Optional[int] = None  # 프로젝트 ID (선택적)
    created_at: datetime  # 생성 시간
    updated_at: datetime  # 수정 시간
    deleted_at: Optional[datetime] = None  # 삭제 시간 (소프트 삭제용, 선택적)

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# 감사 로그(AuditLog) 관련 스키마
# =============================================================================

class AuditLogBase(BaseModel):
    """감사 로그 기본 정보 스키마"""
    action: str  # 수행된 액션 (CREATE, UPDATE, DELETE 등)
    table_name: str  # 대상 테이블명
    row_id: int  # 대상 행 ID
    before_json: Optional[dict] = None  # 변경 전 데이터 (JSON 형태, 선택적)
    after_json: Optional[dict] = None  # 변경 후 데이터 (JSON 형태, 선택적)
    ip: Optional[str] = None  # 클라이언트 IP 주소 (선택적)
    ua: Optional[str] = None  # User Agent (선택적)


class AuditLogCreate(AuditLogBase):
    """감사 로그 생성 시 사용하는 스키마"""
    actor_user_id: int  # 액션을 수행한 사용자 ID (필수)


class AuditLog(AuditLogBase):
    """데이터베이스에서 조회된 감사 로그 정보 스키마"""
    id: int  # 감사 로그 고유 ID
    actor_user_id: int  # 액션을 수행한 사용자 ID
    created_at: datetime  # 생성 시간

    class Config:
        from_attributes = True  # ORM 객체에서 자동 변환 허용


# =============================================================================
# 인증(Authentication) 관련 스키마
# =============================================================================

class Token(BaseModel):
    """JWT 토큰 정보 스키마"""
    access_token: str  # 액세스 토큰
    token_type: str  # 토큰 타입 (예: "bearer")


class TokenData(BaseModel):
    """토큰에서 추출된 데이터 스키마"""
    username: Optional[str] = None  # 사용자명 (선택적)


class LoginRequest(BaseModel):
    """로그인 요청 스키마"""
    email: EmailStr  # 이메일 주소
    password: str  # 비밀번호