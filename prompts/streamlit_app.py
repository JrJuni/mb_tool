import streamlit as st
import user_auth
import db_queries as queries
import db_operations as ops
import db_export as excel_exporter
from pprint import pprint
import hashlib
import time

def generate_session_token(username: str) -> str:
    """세션 토큰 생성"""
    timestamp = str(int(time.time()))
    raw_token = f"{username}_{timestamp}_bdpipe_session"
    return hashlib.md5(raw_token.encode()).hexdigest()[:16]

def validate_session_token(token: str, username: str) -> bool:
    """세션 토큰 검증 (간단한 검증)"""
    if not token or len(token) != 16:
        return False
    # 실제 운영환경에서는 더 강력한 검증이 필요합니다
    return True

def auto_login_from_url():
    """URL 파라미터에서 자동 로그인 시도"""
    query_params = st.query_params
    
    if 'token' in query_params and 'user' in query_params:
        token = query_params['token']
        username = query_params['user']
        
        if validate_session_token(token, username):
            # 사용자 정보 다시 조회
            user_info = user_auth.authenticate_user_by_username(username)
            if user_info and user_info['authenticated'] and user_info['auth_level'] > 0:
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.user_id = user_info['user_id']
                st.session_state.auth_level = user_info['auth_level']
                st.session_state.session_token = token
                return True
    return False

def login_page():
    """로그인 페이지"""
    st.title("🔐 Mobilint CRM - 로그인")
    
    tab1, tab2 = st.tabs(["로그인", "회원가입"])
    
    with tab1:
        st.subheader("로그인")
        username = st.text_input("사용자명", key="login_username")
        password = st.text_input("비밀번호", type="password", key="login_password")
        
        if st.button("로그인", key="login_btn"):
            if username and password:
                if st.session_state.get('debug_mode', False):
                    st.write(f"🐛 DEBUG: 로그인 시도 - 사용자명: '{username}'")
                
                user_info = user_auth.authenticate_user(username, password)
                
                if st.session_state.get('debug_mode', False):
                    st.write(f"🐛 DEBUG: 인증 결과: {user_info}")
                
                if user_info['authenticated']:
                    if user_info['auth_level'] > 0:
                        # 세션 상태 설정
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.session_state.user_id = user_info['user_id']
                        st.session_state.auth_level = user_info['auth_level']
                        
                        # 세션 토큰 생성 및 URL 업데이트
                        token = generate_session_token(username)
                        st.session_state.session_token = token
                        st.query_params.update({"token": token, "user": username})
                        
                        st.success(f"로그인 성공! (권한: {user_auth.get_auth_level_name(user_info['auth_level'])})")
                        st.rerun()
                    else:
                        st.error("계정이 아직 승인되지 않았습니다. 관리자에게 문의하세요.")
                else:
                    st.error("사용자명 또는 비밀번호가 잘못되었습니다.")
            else:
                st.error("사용자명과 비밀번호를 입력하세요.")
    
    with tab2:
        st.subheader("회원가입")
        new_username = st.text_input("사용자명", key="register_username")
        new_password = st.text_input("비밀번호", type="password", key="register_password")
        new_password_confirm = st.text_input("비밀번호 확인", type="password", key="register_password_confirm")
        new_email = st.text_input("이메일 (선택사항)", key="register_email")
        
        if st.button("회원가입 신청", key="register_btn"):
            if new_username and new_password:
                if new_password == new_password_confirm:
                    # 디버그 모드에서만 로그 표시
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🐛 DEBUG: 가입 시도 - 사용자명: '{new_username}', 이메일: '{new_email}'")
                    
                    result = user_auth.register_user(new_username, new_password, new_email)
                    
                    if st.session_state.get('debug_mode', False):
                        st.write(f"🐛 DEBUG: 가입 결과: {result}")
                    
                    if result:
                        st.success("회원가입 신청이 완료되었습니다. 관리자 승인을 기다려주세요.")
                    else:
                        st.error("이미 존재하는 사용자명입니다.")
                else:
                    st.error("비밀번호가 일치하지 않습니다.")
            else:
                st.error("사용자명과 비밀번호를 입력하세요.")

def admin_panel():
    """관리자 패널 - Level 4 이상 접근 가능"""
    if st.session_state.get('auth_level', 0) >= 4:
        st.subheader("👑 관리자 패널")
        
        tab1, tab2 = st.tabs(["승인 대기", "전체 사용자"])
        
        with tab1:
            st.write("**승인 대기 중인 사용자 (Level 0)**")
            pending_users = user_auth.get_pending_users()
            if pending_users:
                for user in pending_users:
                    col1, col2, col3, col4, col5, col6 = st.columns([2, 2, 2, 1, 1, 1])
                    with col1:
                        st.write(f"**{user[0]}**")
                    with col2:
                        st.write(user[1] or "이메일 없음")
                    with col3:
                        st.write(user[2])
                    with col4:
                        # 현재 사용자의 레벨까지만 선택 가능
                        max_level = st.session_state.get('auth_level', 0)
                        available_levels = list(range(1, max_level + 1))
                        level = st.selectbox("레벨", available_levels, key=f"level_{user[0]}")
                    with col5:
                        if st.button("승인", key=f"approve_{user[0]}"):
                            if user_auth.approve_user(st.session_state.username, user[0], level):
                                st.success(f"{user[0]} 레벨 {level} 승인!")
                                st.rerun()
                            else:
                                st.error("승인 실패")
                    with col6:
                        if st.button("삭제", key=f"delete_{user[0]}", type="secondary"):
                            if user_auth.delete_user(st.session_state.username, user[0]):
                                st.success(f"{user[0]} 삭제 완료!")
                                st.rerun()
                            else:
                                st.error("삭제 실패")
            else:
                st.info("승인 대기 중인 사용자가 없습니다.")
        
        with tab2:
            st.write("**전체 사용자 목록**")
            all_users = user_auth.get_all_users()
            if all_users:
                for user in all_users:
                    col1, col2, col3, col4, col5, col6 = st.columns([2, 2, 1, 2, 1, 1])
                    with col1:
                        st.write(f"**{user[0]}**")
                    with col2:
                        st.write(user[1] or "이메일 없음")
                    with col3:
                        st.write(f"Lv.{user[2]}")
                    with col4:
                        st.write(user_auth.get_auth_level_name(user[2]))
                    with col5:
                        if user[0] != 'admin':  # admin 계정은 변경 불가
                            # 현재 사용자의 레벨까지만 선택 가능
                            max_level = st.session_state.get('auth_level', 0)
                            available_levels = list(range(0, max_level + 1))
                            
                            # 현재 사용자 레벨이 선택 가능한 범위에 있는지 확인
                            current_index = user[2] if user[2] in available_levels else 0
                            new_level = st.selectbox("변경", available_levels, 
                                                   index=available_levels.index(current_index), 
                                                   key=f"change_{user[0]}")
                            if new_level != user[2]:
                                if st.button("적용", key=f"apply_{user[0]}"):
                                    if user_auth.approve_user(st.session_state.username, user[0], new_level):
                                        st.success(f"{user[0]} 레벨 변경!")
                                        st.rerun()
                    with col6:
                        if user[0] != 'admin':  # admin 계정은 삭제 불가
                            if st.button("삭제", key=f"delete_all_{user[0]}", type="secondary"):
                                if user_auth.delete_user(st.session_state.username, user[0]):
                                    st.success(f"{user[0]} 삭제 완료!")
                                    st.rerun()
                                else:
                                    st.error("삭제 실패")
            else:
                st.info("등록된 사용자가 없습니다.")

def password_verification_modal():
    """비밀번호 재확인 창"""
    st.subheader("🔒 비밀번호 확인")
    st.write("정보 수정을 위해 현재 비밀번호를 입력해주세요.")
    
    with st.form("password_verification"):
        current_password = st.text_input("현재 비밀번호", type="password")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.form_submit_button("확인", use_container_width=True):
                if current_password:
                    user_info = user_auth.authenticate_user(st.session_state.username, current_password)
                    if user_info['authenticated']:
                        st.session_state.password_verified = True
                        st.success("비밀번호가 확인되었습니다.")
                        st.rerun()
                    else:
                        st.error("비밀번호가 올바르지 않습니다.")
                else:
                    st.error("비밀번호를 입력해주세요.")
        
        with col2:
            if st.form_submit_button("취소", use_container_width=True):
                st.session_state.edit_profile_mode = False
                st.session_state.password_verified = False
                st.rerun()

def edit_profile_page():
    """사용자 정보 수정 페이지"""
    st.subheader("⚙️ 정보 수정")
    
    # 현재 사용자 정보 조회
    user_info = user_auth.get_user_info(st.session_state.username)
    if not user_info['found']:
        st.error("사용자 정보를 찾을 수 없습니다.")
        return
    
    tab1, tab2 = st.tabs(["이메일 수정", "비밀번호 변경"])
    
    with tab1:
        st.write("**현재 이메일 정보 수정**")
        with st.form("email_form"):
            current_email = user_info['email']
            new_email = st.text_input("새 이메일 주소", value=current_email, placeholder="example@domain.com")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("이메일 수정", use_container_width=True):
                    if user_auth.update_user_email(st.session_state.username, new_email):
                        st.success("이메일이 성공적으로 수정되었습니다!")
                        st.rerun()
                    else:
                        st.error("이메일 수정에 실패했습니다. (중복된 이메일일 수 있습니다)")
            
            with col2:
                if st.form_submit_button("취소", use_container_width=True):
                    st.session_state.edit_profile_mode = False
                    st.session_state.password_verified = False
                    st.rerun()
    
    with tab2:
        st.write("**비밀번호 변경**")
        with st.form("password_form"):
            current_password = st.text_input("현재 비밀번호", type="password")
            new_password = st.text_input("새 비밀번호", type="password")
            new_password_confirm = st.text_input("새 비밀번호 확인", type="password")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("비밀번호 변경", use_container_width=True):
                    if current_password and new_password and new_password_confirm:
                        if new_password == new_password_confirm:
                            if len(new_password) >= 4:  # 최소 4자
                                if user_auth.update_user_password(st.session_state.username, current_password, new_password):
                                    st.success("비밀번호가 성공적으로 변경되었습니다!")
                                else:
                                    st.error("현재 비밀번호가 올바르지 않습니다.")
                            else:
                                st.error("새 비밀번호는 최소 4자 이상이어야 합니다.")
                        else:
                            st.error("새 비밀번호가 일치하지 않습니다.")
                    else:
                        st.error("모든 필드를 입력해주세요.")
            
            with col2:
                if st.form_submit_button("취소", use_container_width=True):
                    st.session_state.edit_profile_mode = False
                    st.session_state.password_verified = False
                    st.rerun()

def main_crm():
    """메인 CRM 기능"""
    st.title("📊 Mobilint CRM")
    
    # 정보수정 모드에 따른 페이지 분기
    if st.session_state.edit_profile_mode:
        if not st.session_state.password_verified:
            password_verification_modal()
            return
        else:
            edit_profile_page()
            return
    
    # 상단에 사용자 정보와 버튼들
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        auth_level = st.session_state.get('auth_level', 0)
        level_name = user_auth.get_auth_level_name(auth_level)
        st.write(f"안녕하세요, **{st.session_state.username}**님! (권한: {level_name})")
    with col2:
        if st.button("⚙️ 정보수정"):
            st.session_state.edit_profile_mode = True
            st.session_state.password_verified = False
            st.rerun()
    with col3:
        if st.button("🚪 로그아웃"):
            # 세션 상태 초기화
            for key in ['logged_in', 'username', 'user_id', 'auth_level', 'session_token', 'edit_profile_mode', 'password_verified']:
                if key in st.session_state:
                    del st.session_state[key]
            # URL 파라미터 제거
            st.query_params.clear()
            st.rerun()
    
    # 관리자 패널 - Level 4 이상 접근 가능
    if st.session_state.get('auth_level', 0) >= 4:
        admin_panel()
        st.divider()
    
    # 메인 메뉴
    menu = st.selectbox(
        "작업을 선택하세요:",
        ["전체 회사 목록 보기", "전체 Task 목록 보기", "신규 Task 추가하기", "전체 회사 목록 엑셀 내보내기"]
    )
    
    if menu == "전체 회사 목록 보기":
        st.subheader("🏢 전체 회사 목록")
        companies = queries.get_all_companies_summary()
        if companies:
            st.dataframe(companies)
        else:
            st.info("등록된 회사가 없습니다.")
    
    elif menu == "전체 Task 목록 보기":
        st.subheader("📋 전체 Task 목록")
        tasks = queries.get_all_from_table('Tasks')
        if tasks:
            st.dataframe(tasks)
        else:
            st.info("등록된 Task가 없습니다.")
    
    elif menu == "신규 Task 추가하기":
        st.subheader("➕ 신규 Task 추가")
        
        with st.form("add_task_form"):
            company_name = st.text_input("회사 이름")
            contact_name = st.text_input("담당자 이름 (선택사항)")
            project_name = st.text_input("프로젝트 이름 (선택사항)")
            action_date = st.date_input("액션 날짜")
            agenda = st.text_input("의제")
            action_item = st.text_area("액션 아이템")
            due_date = st.date_input("마감 날짜 (선택사항)", value=None)
            task_type = st.selectbox("작업 유형", 
                                   ["meeting", "contact", "quote", "trial", "tech_inquiry", "delayed"])
            priority = st.selectbox("우선순위", ["high", "medium", "low"])
            memo = st.text_area("메모 (선택사항)")
            
            submitted = st.form_submit_button("Task 추가")
            
            if submitted:
                if company_name and action_date and agenda and action_item:
                    task_id = ops.add_task(
                        company_name=company_name,
                        contact_name=contact_name if contact_name else None,
                        project_name=project_name if project_name else None,
                        user_id=st.session_state.user_id,
                        action_date=str(action_date),
                        agenda=agenda,
                        action_item=action_item,
                        due_date=str(due_date) if due_date else None,
                        task_type=task_type,
                        priority=priority,
                        memo=memo if memo else None
                    )
                    if task_id:
                        st.success(f"Task가 성공적으로 추가되었습니다! (ID: {task_id})")
                    else:
                        st.error("Task 추가에 실패했습니다.")
                else:
                    st.error("필수 필드를 모두 입력해주세요.")
    
    elif menu == "전체 회사 목록 엑셀 내보내기":
        st.subheader("📤 엑셀 내보내기")
        if st.button("엑셀 파일 생성"):
            try:
                filepath = excel_exporter.export_companies_to_excel()
                st.success(f"엑셀 파일이 생성되었습니다: {filepath}")
                
                # 다운로드 버튼
                with open(filepath, 'rb') as f:
                    st.download_button(
                        label="📥 파일 다운로드",
                        data=f.read(),
                        file_name=filepath.split('\\')[-1],
                        mime='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
                    )
            except Exception as e:
                st.error(f"엑셀 파일 생성 중 오류가 발생했습니다: {e}")

def main():
    """메인 함수"""
    st.set_page_config(
        page_title="Mobilint CRM",
        page_icon="🏢",
        layout="wide"
    )
    
    # 세션 상태 초기화
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    if 'debug_mode' not in st.session_state:
        st.session_state.debug_mode = False
    if 'edit_profile_mode' not in st.session_state:
        st.session_state.edit_profile_mode = False
    if 'password_verified' not in st.session_state:
        st.session_state.password_verified = False
    
    # 로그인되지 않은 상태에서 URL 파라미터로 자동 로그인 시도
    if not st.session_state.logged_in:
        auto_login_from_url()
    
    # 우측 상단에 디버그 모드 버튼 추가
    with st.sidebar:
        st.write("---")
        if st.checkbox("🐛 Debug Mode", value=st.session_state.debug_mode):
            st.session_state.debug_mode = True
        else:
            st.session_state.debug_mode = False
    
    # 로그인 상태에 따른 페이지 분기
    if st.session_state.logged_in:
        main_crm()
    else:
        login_page()

if __name__ == "__main__":
    main()