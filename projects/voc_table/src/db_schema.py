import os
import mysql.connector
from mysql.connector import errorcode

# 예: .env 또는 config에서 가져오세요
MYSQL_CONFIG = {
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "password"),
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", "3306")),
    "database": os.getenv("MYSQL_DATABASE", "bdpipe"),
    "autocommit": True,
}

USERS_DDL = """
CREATE TABLE IF NOT EXISTS `Users` (
  `user_id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(191) NOT NULL,
  `password_hash` VARCHAR(255) NOT NULL,
  `user_email` VARCHAR(255),
  `auth_level` TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `is_deleted` TINYINT(1) NOT NULL DEFAULT 0,
  PRIMARY KEY (`user_id`),
  UNIQUE KEY `uq_users_username` (`username`),
  UNIQUE KEY `uq_users_email` (`user_email`),
  CONSTRAINT `chk_users_auth_level` CHECK (`auth_level` BETWEEN 0 AND 5)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"""

def initialize_mysql():
    try:
        conn = mysql.connector.connect(
            user=MYSQL_CONFIG["user"],
            password=MYSQL_CONFIG["password"],
            host=MYSQL_CONFIG["host"],
            port=MYSQL_CONFIG["port"],
        )
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{MYSQL_CONFIG['database']}` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;")
        cur.close()
        conn.close()

        conn = mysql.connector.connect(**MYSQL_CONFIG)
        cur = conn.cursor()
        cur.execute(USERS_DDL)
        cur.close()
        conn.close()
        print("MySQL: Users 테이블 준비 완료")
    except mysql.connector.Error as err:
        if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
            print("MySQL 접근 권한/비밀번호 오류")
        elif err.errno == errorcode.ER_BAD_DB_ERROR:
            print("데이터베이스가 존재하지 않습니다.")
        else:
            print(f"MySQL 오류: {err}")

if __name__ == "__main__":
    initialize_mysql()