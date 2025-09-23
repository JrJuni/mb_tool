import streamlit as st
import requests
import hashlib
import time
import json
import os
import tempfile
from typing import Optional, Dict, Any

# 백엔드 API URL 설정
API_BASE_URL = "http://localhost:8000"

# -----------------------------------------------------------------------------
# Modal compatibility helper (Streamlit versions without st.modal)
# -----------------------------------------------------------------------------
def _modal_ctx(title: str, key: str = "modal"):
    """Return a context manager for a modal-like container.
    Uses st.modal if available; otherwise falls back to a bordered container.
    """
    if hasattr(st, "modal"):
        return st.modal(title, key=key)
    # Fallback: container with a title
    st.markdown(f"### {title}")
    return st.container(border=True)

def get_password_hash(password: str) -> str:
    """간단한 비밀번호 해싱 (개발용)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """비밀번호 검증"""
    return get_password_hash(plain_password) == hashed_password

def generate_session_token(email: str) -> str:
    """세션 토큰 생성"""
    timestamp = str(int(time.time()))
    raw_token = f"{email}_{timestamp}_voc_session"
    return hashlib.md5(raw_token.encode()).hexdigest()[:16]

def validate_session_token(token: str, email: str) -> bool:
    """세션 토큰 검증"""
    if not token or len(token) != 16:
        return False
    # 실제 운영환경에서는 더 강력한 검증이 필요합니다
    return True

def auto_login_from_url():
    """URL 파라미터에서 자동 로그인 시도"""
    query_params = st.query_params
    
    if 'token' in query_params and 'email' in query_params:
        token = query_params['token']
        email = query_params['email']
        
        if validate_session_token(token, email):
            # 사용자 정보 다시 조회
            temp_users = get_temp_users()
            user = temp_users.get(email)
            if user and user['is_active'] and user['auth_level'] > 0:
                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.session_state.username = user['username']
                st.session_state.auth_level = user['auth_level']
                st.session_state.profile_department = user.get('department', '전략팀')
                st.session_state.session_token = token
                return True
    return False

# 사용자 데이터 파일 경로를 모듈 디렉터리 기준으로 고정
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USER_DATA_FILE = os.path.join(BASE_DIR, "user_data.json")

def _default_users():
    return {
        "admin@mobilint.com": {
            "username": "admin",
            "password_hash": get_password_hash("0000"),
            "auth_level": 5,
            "is_active": True,
            "department": "HR"
        },
        "user@example.com": {
            "username": "user",
            "password_hash": get_password_hash("password123"),
            "auth_level": 1,
            "is_active": True,
            "department": "전략팀"
        },
        "manager@example.com": {
            "username": "manager",
            "password_hash": get_password_hash("0000"),
            "auth_level": 3,
            "is_active": True,
            "department": "전략팀"
        }
    }

def load_users_from_file():
    """파일에서 사용자 데이터 로드. 없거나 손상 시 기본 생성 후 저장"""
    try:
        if os.path.exists(USER_DATA_FILE):
            with open(USER_DATA_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        st.warning(f"사용자 데이터 로드 중 문제 발생: {e}. 백업을 시도합니다.")
        # 손상 시 백업에서 복구 시도
        backup_path = USER_DATA_FILE + ".bak"
        if os.path.exists(backup_path):
            try:
                with open(backup_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                save_users_to_file(data)
                return data
            except Exception as e2:
                st.error(f"백업 복구 실패: {e2}")

    # 최초 생성 또는 복구 실패 시 기본값 쓰기
    data = _default_users()
    save_users_to_file(data)
    return data

def save_users_to_file(users_data):
    """파일에 사용자 데이터 저장 (원자적 쓰기 + 백업)"""
    try:
        os.makedirs(os.path.dirname(USER_DATA_FILE), exist_ok=True)

        # 임시 파일에 먼저 기록
        dir_name = os.path.dirname(USER_DATA_FILE) or BASE_DIR
        fd, temp_path = tempfile.mkstemp(prefix="user_data_", suffix=".tmp", dir=dir_name)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp:
                json.dump(users_data, tmp, ensure_ascii=False, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())

            # 기존 파일 백업
            if os.path.exists(USER_DATA_FILE):
                backup_path = USER_DATA_FILE + ".bak"
                try:
                    with open(USER_DATA_FILE, 'r', encoding='utf-8') as src, open(backup_path, 'w', encoding='utf-8') as dst:
                        dst.write(src.read())
                except Exception as be:
                    st.warning(f"백업 생성 실패: {be}")

            # 원자적 교체
            os.replace(temp_path, USER_DATA_FILE)
        finally:
            # temp_path가 남아있으면 정리
            if os.path.exists(temp_path):
                try:
                    os.remove(temp_path)
                except Exception:
                    pass
    except Exception as e:
        st.error(f"사용자 데이터 저장 실패: {e}")

def get_temp_users():
    """사용자 데이터 가져오기 (파일 기반)"""
    if 'temp_users' not in st.session_state:
        st.session_state.temp_users = load_users_from_file()
    return st.session_state.temp_users

def authenticate_user(email: str, password: str) -> Optional[Dict[str, Any]]:
    """사용자 인증"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    if not user:
        return None
    
    if not verify_password(password, user["password_hash"]):
        return None
    
    if not user["is_active"]:
        return None
    
    if user["auth_level"] == 0:
        return None
    
    return {
        "email": email,
        "username": user["username"],
        "auth_level": user["auth_level"],
        "authenticated": True,
        "department": user.get("department", "전략팀")
    }

def check_password_reset_needed(email: str, password: str) -> bool:
    """비밀번호 재설정이 필요한지 확인"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    if not user:
        return False
    return verify_password("0000", user["password_hash"]) and password == "0000"

def update_user_password(email: str, new_password: str) -> bool:
    """사용자 비밀번호 업데이트"""
    temp_users = get_temp_users()
    if email in temp_users:
        temp_users[email]["password_hash"] = get_password_hash(new_password)
        save_users_to_file(temp_users)  # 파일에 저장
        return True
    return False

def register_user(email: str, username: str, password: str) -> bool:
    """사용자 회원가입"""
    temp_users = get_temp_users()
    if email in temp_users:
        return False
    
    temp_users[email] = {
        "username": username,
        "password_hash": get_password_hash(password),
        "auth_level": 0,  # 승인 대기
        "is_active": True
    }
    save_users_to_file(temp_users)  # 파일에 저장
    return True

def get_users_with_reset_permission(user_auth_level: int):
    """비밀번호 초기화 권한이 있는 사용자 목록"""
    temp_users = get_temp_users()
    return [
        {"email": email, "username": data["username"], "auth_level": data["auth_level"]}
        for email, data in temp_users.items()
        if data["auth_level"] >= 3 and data["auth_level"] >= user_auth_level and data["is_active"]
    ]

def reset_user_password(email: str, username: str, actor_email: str) -> bool:
    """사용자 비밀번호 초기화"""
    temp_users = get_temp_users()
    user = temp_users.get(email)
    actor = temp_users.get(actor_email)
    
    if not user or not actor:
        return False
    
    if user["username"] != username:
        return False
    
    if actor["auth_level"] < 3 or actor["auth_level"] < user["auth_level"]:
        return False
    
    temp_users[email]["password_hash"] = get_password_hash("0000")
    save_users_to_file(temp_users)  # 파일에 저장
    return True

def password_reset_page():
    """비밀번호 재설정 페이지"""
    st.subheader("🔑 새 비밀번호 설정")
    st.warning("보안을 위해 새로운 비밀번호를 설정해 주세요.")
    
    with st.form("password_reset_form"):
        new_password = st.text_input("새 비밀번호 (6자리 이상)", type="password")
        confirm_password = st.text_input("비밀번호 확인", type="password")
        
        if st.form_submit_button("비밀번호 설정"):
            if len(new_password) < 6:
                st.error("비밀번호는 6자리 이상이어야 합니다.")
            elif new_password != confirm_password:
                st.error("비밀번호가 일치하지 않습니다.")
            elif new_password == "0000":
                st.error("보안을 위해 0000은 사용할 수 없습니다.")
            else:
                if update_user_password(st.session_state.user_email, new_password):
                    # 비밀번호 변경 후 자동 로그인 처리
                    temp_users = get_temp_users()
                    user = temp_users.get(st.session_state.user_email)
                    
                    st.session_state.logged_in = True
                    st.session_state.username = user["username"]
                    st.session_state.auth_level = user["auth_level"]
                    st.session_state.password_reset_needed = False
                    
                    # 세션 토큰 생성 및 URL 업데이트
                    token = generate_session_token(st.session_state.user_email)
                    st.session_state.session_token = token
                    st.query_params.update({"token": token, "email": st.session_state.user_email})
                    
                    st.success("비밀번호가 성공적으로 변경되었습니다!")
                    st.rerun()
                else:
                    st.error("비밀번호 변경에 실패했습니다.")

def login_page():
    """로그인 페이지"""
    st.title("🏢 VOC Management System")
    
    tab1, tab2, tab3 = st.tabs(["로그인", "회원가입", "비밀번호 초기화"])
    
    with tab1:
        st.subheader("로그인")
        email = st.text_input("이메일", key="login_email")
        password = st.text_input("비밀번호", type="password", key="login_password")
        
        if st.button("로그인", key="login_btn"):
            if email and password:
                # 비밀번호 재설정 필요 확인
                if check_password_reset_needed(email, password):
                    st.session_state.user_email = email
                    st.session_state.password_reset_needed = True
                    st.rerun()
                    return
                
                user_info = authenticate_user(email, password)
                if user_info and user_info["authenticated"]:
                    st.session_state.logged_in = True
                    st.session_state.user_email = email
                    st.session_state.username = user_info["username"]
                    st.session_state.auth_level = user_info["auth_level"]
                    
                    # 세션 토큰 생성 및 URL 업데이트
                    token = generate_session_token(email)
                    st.session_state.session_token = token
                    st.query_params.update({"token": token, "email": email})
                    
                    st.success("로그인 성공!")
                    st.rerun()
                else:
                    st.error("잘못된 비밀번호입니다.")
            else:
                st.error("이메일과 비밀번호를 입력하세요.")
    
    with tab2:
        st.subheader("회원가입")
        reg_email = st.text_input("이메일", key="reg_email")
        reg_username = st.text_input("사용자명", key="reg_username")
        reg_password = st.text_input("비밀번호", type="password", key="reg_password")
        
        if st.button("회원가입 신청", key="register_btn"):
            if reg_email and reg_username and reg_password:
                if register_user(reg_email, reg_username, reg_password):
                    st.success("회원가입 신청이 완료되었습니다. 관리자 승인을 기다려주세요.")
                else:
                    st.error("이미 존재하는 이메일입니다.")
            else:
                st.error("모든 필드를 입력하세요.")
    
    with tab3:
        st.subheader("비밀번호 초기화 요청")
        reset_email = st.text_input("이메일", key="reset_email")
        reset_username = st.text_input("사용자명", key="reset_username")
        
        if st.button("초기화 요청", key="reset_request_btn"):
            if reset_email and reset_username:
                temp_users = get_temp_users()
                user = temp_users.get(reset_email)
                if user and user["username"] == reset_username:
                    st.success("비밀번호 초기화 요청이 접수되었습니다.")
                    
                    # 권한이 있는 사용자 목록 표시
                    reset_users = get_users_with_reset_permission(user["auth_level"])
                    if reset_users:
                        st.write("**초기화 권한이 있는 사용자:**")
                        for reset_user in reset_users:
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                st.write(f"- {reset_user['username']} ({reset_user['email']}) - Level {reset_user['auth_level']}")
                            with col2:
                                if st.button("초기화", key=f"reset_{reset_user['email']}"):
                                    if reset_user_password(reset_email, reset_username, reset_user['email']):
                                        st.success("비밀번호가 0000으로 초기화되었습니다.")
                                        st.rerun()
                                    else:
                                        st.error("초기화에 실패했습니다.")
                    else:
                        st.warning("초기화 권한이 있는 사용자가 없습니다.")
                else:
                    st.error("이메일 또는 사용자명이 올바르지 않습니다.")
            else:
                st.error("이메일과 사용자명을 입력하세요.")

def voc_table_page():
    """VOC 테이블 페이지"""
    st.title("📊 VOC Management Dashboard")
    
    # 상단 사용자 정보 (우측 정렬, 버튼 간 간격 축소)
    top_left, top_settings, top_logout = st.columns([6.8, 1.0, 1.4])
    with top_left:
        st.write(f"안녕하세요, **{st.session_state.username}**님! (Level {st.session_state.auth_level})")
    with top_settings:
        # 수평 오프셋을 위한 서브 컬럼 구성 (약 50px 여백 근사)
        sub_spacer, sub_btn = st.columns([0.45, 0.55])
        with sub_btn:
            if st.button("⚙️ 설정"):
                st.session_state["show_settings_modal"] = True
    with top_logout:
        # 로그아웃 버튼도 동일하게 약 40px 오른쪽으로 오프셋
        lo_spacer, lo_btn = st.columns([0.35, 0.65])
        with lo_btn:
            if st.button("🚪 로그아웃"):
                # 세션 상태 초기화
                for key in ['logged_in', 'user_email', 'username', 'auth_level', 'session_token']:
                    if key in st.session_state:
                        del st.session_state[key]
                # URL 파라미터 제거
                st.query_params.clear()
                st.rerun()
    
    # 설정 모달 표시
    if st.session_state.get("show_settings_modal", False):
        with _modal_ctx("설정", key="settings_modal"):
            _render_settings_modal_content()

    st.divider()
    
    # VOC 테이블 (임시 데이터)
    st.subheader("VOC 목록")

    # 테이블 헤더 가운데 정렬을 위한 경량 CSS 주입
    st.markdown(
        """
        <style>
        /* st.dataframe 헤더 가운데 정렬 */
        div[data-testid="stDataFrame"] thead tr th div {
            display: flex; justify-content: center; align-items: center;
        }
        div[data-testid="stDataFrame"] thead tr th {
            text-align: center !important;
        }
        /* 버튼 텍스트 줄바꿈 방지 및 반응형 폰트/패딩 */
        div.stButton > button { white-space: nowrap; width: 100%; }
        @media (max-width: 1400px) {
            div.stButton > button { font-size: 0.9rem; padding: 0.35rem 0.7rem; }
        }
        @media (max-width: 1100px) {
            div.stButton > button { font-size: 0.8rem; padding: 0.3rem 0.6rem; }
        }
        
        </style>
        """,
        unsafe_allow_html=True,
    )
    
    # 임시 VOC 데이터
    voc_data = [
        {"ID": 1, "날짜": "2024-01-15", "회사": "ABC Corp", "내용": "시스템 오류 문의", "상태": "진행중", "우선순위": "높음", "담당자": "김철수"},
        {"ID": 2, "날짜": "2024-01-14", "회사": "XYZ Ltd", "내용": "기능 개선 요청", "상태": "완료", "우선순위": "보통", "담당자": "이영희"},
        {"ID": 3, "날짜": "2024-01-13", "회사": "DEF Inc", "내용": "성능 최적화 요청", "상태": "대기", "우선순위": "낮음", "담당자": "박민수"},
    ]
    
    # DataFrame으로 변환 후 컬럼 폭 조정
    import pandas as pd
    df = pd.DataFrame(voc_data)

    # 폭 가이드
    # - ID: 6자리 고려 (약 70px)
    # - 날짜: 10자리 고려 (약 110px)
    # - 상태/우선순위/담당자: 축소 (각 100px 내외)
    # - 내용: 그만큼 넓게 (예: 420px)
    # - 회사: 보통 (150px)
    st.dataframe(
        df,
        use_container_width=True,
        column_config={
            "ID": st.column_config.NumberColumn("ID", width=42),
            "날짜": st.column_config.TextColumn("날짜", width=66),
            "회사": st.column_config.TextColumn("회사", width=200),
            "내용": st.column_config.TextColumn("내용", width=560),
            "상태": st.column_config.TextColumn("상태", width=60),
            "우선순위": st.column_config.TextColumn("우선순위", width=60),
            "담당자": st.column_config.TextColumn("담당자", width=66),
        },
        hide_index=True,
    )
    
    # VOC 추가 기능
    with st.expander("새 VOC 추가"):
        with st.form("add_voc_form"):
            col1, col2 = st.columns(2)
            with col1:
                voc_date = st.date_input("날짜")
                voc_company = st.text_input("회사명")
            with col2:
                voc_priority = st.selectbox("우선순위", ["낮음", "보통", "높음", "긴급"])
                voc_status = st.selectbox("상태", ["대기", "진행중", "완료", "보류"])
            
            voc_content = st.text_area("VOC 내용")
            voc_action = st.text_area("액션 아이템")
            
            if st.form_submit_button("VOC 추가"):
                st.success("VOC가 추가되었습니다! (실제 DB 연동 시 저장됩니다)")

def _render_settings_modal_content():
    """설정 모달 내부 UI 렌더링"""
    st.subheader("회원 정보")
    # 오른쪽 상단에 회원정보 수정 버튼
    header_col1, header_col2 = st.columns([3, 1])
    with header_col2:
        if st.button("회원정보 수정"):
            st.session_state["reauth_context"] = "edit_profile"
            st.session_state["show_reauth_modal"] = True

    st.divider()

    # 실제 사용자 정보 렌더링 (세션 기준)
    st.write(f"이름 {st.session_state.get('username', '-')}")
    st.write(f"부서 {st.session_state.get('profile_department', '전략팀')}")
    st.write(f"이메일 {st.session_state.get('user_email', 'unknown@mail.com')}")

    st.write("")
    btn_col1, btn_col2 = st.columns([1, 1])
    with btn_col1:
        # LV3 이상만 노출
        if st.session_state.get('auth_level', 0) >= 3:
            if st.button("회원관리"):
                st.session_state["reauth_context"] = "manage_users"
                st.session_state["show_reauth_modal"] = True
    with btn_col2:
        if st.button("닫기"):
            st.session_state["show_settings_modal"] = False

    # 하위 모달 렌더링
    _render_reauth_modal()
    _render_edit_profile_modal()
    _render_user_management_modal()

def _render_reauth_modal():
    """민감 작업 전 재인증 모달"""
    if not st.session_state.get("show_reauth_modal", False):
        return
    title = "본인 확인"
    with _modal_ctx(title, key="reauth_modal"):
        st.write("보안을 위해 현재 비밀번호를 다시 입력해 주세요.")
        with st.form("reauth_form"):
            current_pw = st.text_input("현재 비밀번호", type="password")
            col_a, col_b = st.columns([1,1])
            submitted = col_a.form_submit_button("확인")
            cancel = col_b.form_submit_button("취소")
        if submitted:
            # 파일 기반 사용자 인증
            user_email = st.session_state.get("user_email")
            temp_users = get_temp_users()
            user = temp_users.get(user_email)
            if user and verify_password(current_pw, user.get("password_hash", "")):
                ctx = st.session_state.get("reauth_context")
                st.session_state["show_reauth_modal"] = False
                st.session_state["show_settings_modal"] = True
                if ctx == "edit_profile":
                    st.session_state["show_edit_profile_modal"] = True
                elif ctx == "manage_users":
                    st.session_state["show_user_mgmt_modal"] = True
                st.rerun()
            else:
                st.error("비밀번호가 올바르지 않습니다.")
        if cancel:
            st.session_state["show_reauth_modal"] = False
            st.session_state.pop("reauth_context", None)
            st.session_state["show_settings_modal"] = True
            st.rerun()

def _render_edit_profile_modal():
    """회원정보 수정 모달"""
    if not st.session_state.get("show_edit_profile_modal", False):
        return
    with _modal_ctx("회원정보 수정", key="edit_profile_modal"):
        temp_users = get_temp_users()
        email = st.session_state.get("user_email", "")
        username = st.session_state.get("username", "")
        # 임시로 부서는 세션에 없으므로 로컬 상태로 관리
        if "profile_department" not in st.session_state:
            st.session_state["profile_department"] = "전략팀"

        with st.form("edit_profile_form"):
            name_val = st.text_input("이름", value=username)
            dept_val = st.text_input("부서", value=st.session_state["profile_department"]) 
            new_pw = st.text_input("새 비밀번호", type="password")
            new_pw2 = st.text_input("비밀번호 확인", type="password")
            col_a, col_b = st.columns([1,1])
            apply_clicked = col_a.form_submit_button("적용")
            cancel_clicked = col_b.form_submit_button("취소")

        if apply_clicked:
            # 이름/부서 업데이트
            st.session_state["username"] = name_val
            st.session_state["profile_department"] = dept_val
            # 파일 저장 (이름만 반영)
            if email in temp_users:
                temp_users[email]["username"] = name_val
                temp_users[email]["department"] = dept_val
                if new_pw or new_pw2:
                    if len(new_pw) < 6:
                        st.error("비밀번호는 6자리 이상이어야 합니다.")
                        st.stop()
                    if new_pw != new_pw2:
                        st.error("비밀번호가 일치하지 않습니다.")
                        st.stop()
                    temp_users[email]["password_hash"] = get_password_hash(new_pw)
                save_users_to_file(temp_users)
                # 세션 캐시 동기화
                st.session_state["temp_users"] = temp_users
            st.success("프로필이 업데이트되었습니다.")
            st.session_state["show_edit_profile_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()
        if cancel_clicked:
            st.session_state["show_edit_profile_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()

def _render_user_management_modal():
    """회원관리 모달 (LV3+)"""
    if not st.session_state.get("show_user_mgmt_modal", False):
        return
    with _modal_ctx("회원관리", key="user_mgmt_modal"):
        temp_users = get_temp_users()
        current_level = st.session_state.get("auth_level", 0)

        st.subheader("회원가입 신청 리스트")
        st.markdown("---")
        # 승인 대기: auth_level == 0
        pending = [(email, data) for email, data in temp_users.items() if data.get("auth_level", 0) == 0]
        if not pending:
            st.write("승인 대기 중인 사용자가 없습니다.")
        else:
            for email, data in pending:
                c1, c2, c3 = st.columns([2,3,1])
                c1.write(f"{data.get('username','-')} ({email})")
                c2.write("p.w 제외")
                if c3.button("승인", key=f"approve_{email}"):
                    # 레벨 선택 팝업: 현재 사용자 레벨까지 선택 가능
                    st.session_state["approve_target_email"] = email
                    st.session_state["show_approve_modal"] = True
                    st.experimental_rerun()

        st.subheader("직원 리스트")
        st.markdown("---")
        # 자신 레벨 이하만 표시 (p.w 제외 표기)
        employees = [
            (email, data) for email, data in temp_users.items()
            if data.get("auth_level", 0) <= current_level and data.get("auth_level", 0) > 0
        ]
        if not employees:
            st.write("표시할 직원이 없습니다.")
        else:
            for email, data in employees:
                c1, c2, c3 = st.columns([2,3,1])
                c1.write(f"{data.get('username','-')} ({email})")
                c2.write("p.w 제외")
                if c3.button("권한수정", key=f"role_{email}"):
                    st.session_state["edit_role_target"] = email
                    st.session_state["show_role_edit_inline"] = True
            # 권한 수정 인라인 폼
            if st.session_state.get("show_role_edit_inline") and st.session_state.get("edit_role_target"):
                target_email = st.session_state["edit_role_target"]
                levels = [0,1,2,3,4,5]
                new_level = st.selectbox("권한 레벨 선택", levels, index=levels.index(temp_users[target_email]["auth_level"]))
                colx, coly = st.columns([1,1])
                if colx.button("적용", key="apply_role"):
                    # 자신보다 높은 레벨은 불가
                    if new_level > current_level:
                        st.error("자신보다 높은 레벨로 설정할 수 없습니다.")
                    else:
                        temp_users[target_email]["auth_level"] = new_level
                        save_users_to_file(temp_users)
                        # 세션 캐시 및 본인 변경 시 세션 레벨 반영
                        st.session_state["temp_users"] = temp_users
                        if target_email == st.session_state.get("user_email"):
                            st.session_state["auth_level"] = new_level
                        st.success("권한이 변경되었습니다.")
                        st.session_state.pop("show_role_edit_inline", None)
                        st.session_state.pop("edit_role_target", None)
                        st.session_state["show_settings_modal"] = True
                        st.experimental_rerun()
                if coly.button("취소", key="cancel_role"):
                    st.session_state.pop("show_role_edit_inline", None)
                    st.session_state.pop("edit_role_target", None)
                    st.session_state["show_settings_modal"] = True
                    st.experimental_rerun()

        st.write("")
        col_ok, col_cancel = st.columns([1,1])
        if col_ok.button("적용"):
            st.session_state["show_user_mgmt_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()
        if col_cancel.button("취소"):
            st.session_state["show_user_mgmt_modal"] = False
            st.session_state["show_settings_modal"] = True
            st.rerun()

    # 승인 레벨 선택 모달 (회원관리 내부 플로우)
    if st.session_state.get("show_approve_modal", False) and st.session_state.get("approve_target_email"):
        target_email = st.session_state["approve_target_email"]
        with _modal_ctx("승인 레벨 선택", key="approve_level_modal"):
            current_level = st.session_state.get("auth_level", 1)
            levels = list(range(1, current_level + 1))
            st.write("승인할 권한 레벨을 선택해 주세요.")
            new_level = st.selectbox("권한 레벨", levels, index=0)
            ca, cb = st.columns([1,1])
            if ca.button("확인", key="approve_apply"):
                temp_users = get_temp_users()
                if target_email in temp_users:
                    temp_users[target_email]["auth_level"] = new_level
                    save_users_to_file(temp_users)
                st.session_state["show_approve_modal"] = False
                st.session_state.pop("approve_target_email", None)
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.experimental_rerun()
            if cb.button("취소", key="approve_cancel"):
                st.session_state["show_approve_modal"] = False
                st.session_state.pop("approve_target_email", None)
                st.session_state["show_user_mgmt_modal"] = True
                st.session_state["show_settings_modal"] = True
                st.experimental_rerun()

def main():
    """메인 함수"""
    st.set_page_config(
        page_title="VOC Management System",
        page_icon="🏢",
        layout="wide"
    )
    
    # 세션 상태 초기화
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'password_reset_needed' not in st.session_state:
        st.session_state.password_reset_needed = False
    
    # 로그인되지 않은 상태에서 URL 파라미터로 자동 로그인 시도
    if not st.session_state.logged_in:
        auto_login_from_url()
    
    # 페이지 라우팅
    if st.session_state.get('password_reset_needed', False):
        password_reset_page()
    elif st.session_state.get('logged_in', False):
        voc_table_page()
    else:
        login_page()

if __name__ == "__main__":
    main()