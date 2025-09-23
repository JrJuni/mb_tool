# 필요한 라이브러리 import
from typing import Optional, Literal, Any
from datetime import datetime, date
from pydantic import BaseModel, EmailStr, conint
from enum import Enum

# =============================================================================
# 공통 Enum 및 타입 정의
# =============================================================================

class VOCStatus(str, Enum):
    """VOC 상태 Enum"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    DONE = "done"
    ON_HOLD = "on_hold"

class VOCPriority(str, Enum):
    """VOC 우선순위 Enum"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"

class AuditAction(str, Enum):
    """감사 로그 액션 Enum"""
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    EXPORT = "export"
    IMPORT = "import"

# =============================================================================
# 사용자(User) 관련 스키마
# =============================================================================

class UserBase(BaseModel):
    """사용자 기본 정보 스키마"""
    email: EmailStr  # 이메일 주소 (유효성 검증 포함, unique 인덱스 필요)
    username: str  # 사용자명 (unique 인덱스 필요)
    auth_level: conint(ge=0, le=5) = 0  # 권한 레벨 (0~5 범위, 기본값: 0)
    is_active: bool = True  # 계정 활성화 상태 (기본값: True)
    department: Optional[str] = None  # 부서 (선택적)


class UserCreate(UserBase):
    """사용자 생성 시 사용하는 스키마"""
    password: str  # 비밀번호


class UserUpdate(BaseModel):
    """사용자 정보 수정 시 사용하는 스키마 (모든 필드 선택적)"""
    email: Optional[EmailStr] = None  # 이메일 (선택적)
    username: Optional[str] = None  # 사용자명 (선택적)
    auth_level: Optional[conint(ge=0, le=5)] = None  # 권한 레벨 (0~5 범위, 선택적)
    is_active: Optional[bool] = None  # 활성화 상태 (선택적)
    password: Optional[str] = None  # 비밀번호 (선택적)
    department: Optional[str] = None  # 부서 (선택적)


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
    name: str  # 회사명 (unique 인덱스 권장)
    domain: Optional[str] = None  # 도메인 (선택적)
    revenue: Optional[str] = None  # 매출 (선택적)
    employee: Optional[int] = None  # 직원 수 (선택적, nullable 허용)
    nation: Optional[str] = None  # 국가 (선택적, 프리 텍스트 OK)


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
    email: Optional[EmailStr] = None  # 이메일 (선택적, nullable, 중복 가능)
    phone: Optional[str] = None  # 전화번호 (선택적)
    note: Optional[str] = None  # 메모 (선택적)


class ContactCreate(ContactBase):
    """연락처 생성 시 사용하는 스키마"""
    company_id: int  # 소속 회사 ID (필수, FK with ON DELETE RESTRICT)


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
    ai_model: Optional[str] = None  # AI 모델 (선택적, 프리 텍스트 OK)
    perf: Optional[str] = None  # 성능 (선택적, 프리 텍스트 OK)
    power: Optional[str] = None  # 전력 (선택적, 프리 텍스트 OK)
    size: Optional[str] = None  # 크기 (선택적, 프리 텍스트 OK)
    price: Optional[str] = None  # 요구가격 (선택적, 프리 텍스트 OK)
    requirements: Optional[str] = None  # 요구사항 (선택적)
    competitors: Optional[str] = None  # 경쟁사 (선택적)
    result: Optional[str] = None  # 결과 (선택적)
    root_cause: Optional[str] = None  # 근본 원인 (선택적)

class ProjectCreate(ProjectBase):
    """프로젝트 생성 시 사용하는 스키마"""
    company_id: int  # 소속 회사 ID (필수, FK)

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
    root_cause: Optional[str] = None  # 근본 원인 (선택적)

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
    status: VOCStatus = VOCStatus.IN_PROGRESS  # 상태 (Enum, 기본값: in_progress)
    priority: VOCPriority = VOCPriority.MEDIUM  # 우선순위 (Enum, 기본값: medium)
    assignee_user_id: int  # 담당자 ID (필수, 로그인 사용자 자동 할당)
    ai_summary: Optional[str] = None  # AI 요약 결과 (선택적, 요약 플로우용)


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
    status: Optional[VOCStatus] = None  # 상태 (선택적)
    priority: Optional[VOCPriority] = None  # 우선순위 (선택적)
    assignee_user_id: Optional[int] = None  # 담당자 ID (선택적, 담당자 변경 시 사용)
    ai_summary: Optional[str] = None  # AI 요약 결과 (선택적)


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
    action: AuditAction  # 수행된 액션 (Enum: create/update/delete/login/export/import)
    table_name: str  # 대상 테이블명
    row_id: int  # 대상 행 ID
    before_json: Optional[dict[str, Any]] = None  # 변경 전 데이터 (dict[str, Any], 선택적)
    after_json: Optional[dict[str, Any]] = None  # 변경 후 데이터 (dict[str, Any], 선택적)
    ip: Optional[str] = None  # 클라이언트 IP 주소 (선택적)
    ua: Optional[str] = None  # User Agent (선택적)


class AuditLogCreate(AuditLogBase):
    """감사 로그 생성 시 사용하는 스키마"""
    actor_user_id: int  # 액션을 수행한 사용자 ID (필수, FK)


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