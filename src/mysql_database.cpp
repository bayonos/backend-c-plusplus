#include "mysql_database.hpp"

#if __has_include(<mysqld_error.h>)
#include <mysqld_error.h>
#endif
#ifndef ER_DUP_ENTRY
#define ER_DUP_ENTRY 1062
#endif

#include <array>
#include <cstring>
#include <stdexcept>
#include <type_traits>

namespace auth {

namespace {

using MysqlBool = std::remove_pointer_t<decltype(MYSQL_BIND{}.is_null)>;

class MysqlStmtGuard {
public:
    explicit MysqlStmtGuard(MYSQL* conn, const char* sql) {
        stmt_ = mysql_stmt_init(conn);
        if (!stmt_) {
            throw std::runtime_error("mysql_stmt_init failed");
        }
        if (mysql_stmt_prepare(stmt_, sql, static_cast<unsigned long>(std::strlen(sql))) != 0) {
            std::string msg = mysql_stmt_error(stmt_);
            mysql_stmt_close(stmt_);
            stmt_ = nullptr;
            throw std::runtime_error("MySQL prepare failed: " + msg);
        }
    }
    ~MysqlStmtGuard() {
        if (stmt_) {
            mysql_stmt_close(stmt_);
        }
    }
    MysqlStmtGuard(const MysqlStmtGuard&) = delete;
    MysqlStmtGuard& operator=(const MysqlStmtGuard&) = delete;

    MYSQL_STMT* get() const { return stmt_; }

private:
    MYSQL_STMT* stmt_ = nullptr;
};

void bindStringParam(MYSQL_BIND& b, const std::string& val, unsigned long& len, MysqlBool& is_null) {
    std::memset(&b, 0, sizeof(b));
    b.buffer_type = MYSQL_TYPE_STRING;
    b.buffer = const_cast<char*>(val.data());
    b.buffer_length = static_cast<unsigned long>(val.size());
    len = static_cast<unsigned long>(val.size());
    is_null = 0;
    b.length = &len;
    b.is_null = &is_null;
}

void bindNullableStringParam(MYSQL_BIND& b, const std::string& val, unsigned long& len, MysqlBool& is_null) {
    std::memset(&b, 0, sizeof(b));
    b.buffer_type = MYSQL_TYPE_STRING;
    b.buffer = const_cast<char*>(val.data());
    b.buffer_length = static_cast<unsigned long>(val.size());
    len = static_cast<unsigned long>(val.size());
    is_null = val.empty() ? 1 : 0;
    b.length = &len;
    b.is_null = &is_null;
}

void bindInt64Param(MYSQL_BIND& b, int64_t& val) {
    std::memset(&b, 0, sizeof(b));
    b.buffer_type = MYSQL_TYPE_LONGLONG;
    b.buffer = &val;
    b.is_unsigned = 0;
}

void bindOutString(MYSQL_BIND& b, char* buf, unsigned long cap, unsigned long& len, MysqlBool& is_null) {
    std::memset(&b, 0, sizeof(b));
    b.buffer_type = MYSQL_TYPE_STRING;
    b.buffer = buf;
    b.buffer_length = cap;
    b.length = &len;
    b.is_null = &is_null;
}

std::string extractString(const char* buf, unsigned long len, MysqlBool is_null, unsigned long cap) {
    if (is_null) {
        return "";
    }
    unsigned long actual = (len < cap) ? len : (cap - 1);
    return std::string(buf, actual);
}

}  // namespace

MysqlDatabase::MysqlDatabase(std::string host,
                             uint16_t port,
                             std::string user,
                             std::string password,
                             std::string database)
    : host_(std::move(host)),
      port_(port),
      user_(std::move(user)),
      password_(std::move(password)),
      database_(std::move(database)) {
    std::lock_guard<std::mutex> lock(mutex_);
    connectLocked();
}

MysqlDatabase::~MysqlDatabase() {
    if (conn_) {
        mysql_close(conn_);
        conn_ = nullptr;
    }
}

void MysqlDatabase::connectLocked() {
    if (conn_) {
        mysql_close(conn_);
        conn_ = nullptr;
    }
    conn_ = mysql_init(nullptr);
    if (!conn_) {
        throw std::runtime_error("mysql_init failed");
    }

    unsigned int timeout_sec = 5;
    mysql_options(conn_, MYSQL_OPT_CONNECT_TIMEOUT, &timeout_sec);

    if (!mysql_real_connect(conn_,
                            host_.c_str(),
                            user_.c_str(),
                            password_.c_str(),
                            database_.c_str(),
                            port_,
                            nullptr,
                            0)) {
        std::string err = mysql_error(conn_);
        mysql_close(conn_);
        conn_ = nullptr;
        throw std::runtime_error("Failed to connect to MySQL (" + host_ + ":" +
                                 std::to_string(port_) + "/" + database_ + "): " + err);
    }
    mysql_set_character_set(conn_, "utf8mb4");
}

void MysqlDatabase::ensureConnectedLocked() {
    if (!conn_ || mysql_ping(conn_) != 0) {
        connectLocked();
    }
}

void MysqlDatabase::execQueryLocked(const std::string& sql) {
    ensureConnectedLocked();
    if (mysql_query(conn_, sql.c_str()) != 0) {
        throw std::runtime_error(std::string("MySQL query failed: ") + mysql_error(conn_));
    }
}

void MysqlDatabase::initSchema() {
    std::lock_guard<std::mutex> lock(mutex_);
    execQueryLocked(R"SQL(
        CREATE TABLE IF NOT EXISTS users (
            id INT NOT NULL AUTO_INCREMENT,
            username VARCHAR(50) NOT NULL,
            password VARCHAR(255) NOT NULL,
            full_name VARCHAR(100) NOT NULL,
            email VARCHAR(120) DEFAULT NULL,
            phone VARCHAR(30) DEFAULT NULL,
            role ENUM('owner','manager','staff','admin') NOT NULL DEFAULT 'owner',
            status ENUM('active','inactive') NOT NULL DEFAULT 'active',
            created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY username (username)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    )SQL");

    execQueryLocked(R"SQL(
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id BIGINT NOT NULL AUTO_INCREMENT,
            user_id INT NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expires_at BIGINT NOT NULL,
            revoked TINYINT(1) NOT NULL DEFAULT 0,
            created_at BIGINT NOT NULL,
            PRIMARY KEY (id),
            UNIQUE KEY uk_refresh_tokens_hash (token_hash),
            KEY idx_refresh_tokens_user_id (user_id),
            CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id)
                REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    )SQL");
}

std::optional<UserRecord> MysqlDatabase::fetchSingleUserStmt(MYSQL_STMT* stmt) {
    if (mysql_stmt_execute(stmt) != 0) {
        throw std::runtime_error(std::string("MySQL execute failed: ") + mysql_stmt_error(stmt));
    }
    if (mysql_stmt_store_result(stmt) != 0) {
        throw std::runtime_error(std::string("MySQL store_result failed: ") + mysql_stmt_error(stmt));
    }

    int64_t id = 0;
    char username[128]{};
    char password[512]{};
    char full_name[256]{};
    char email[256]{};
    char phone[64]{};
    char role[32]{};
    char status[32]{};
    char created_at[64]{};

    std::array<unsigned long, 9> lengths{};
    std::array<MysqlBool, 9> is_nulls{};
    std::array<MYSQL_BIND, 9> out{};

    std::memset(&out[0], 0, sizeof(out[0]));
    out[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out[0].buffer = &id;
    out[0].is_null = &is_nulls[0];

    bindOutString(out[1], username, sizeof(username), lengths[1], is_nulls[1]);
    bindOutString(out[2], password, sizeof(password), lengths[2], is_nulls[2]);
    bindOutString(out[3], full_name, sizeof(full_name), lengths[3], is_nulls[3]);
    bindOutString(out[4], email, sizeof(email), lengths[4], is_nulls[4]);
    bindOutString(out[5], phone, sizeof(phone), lengths[5], is_nulls[5]);
    bindOutString(out[6], role, sizeof(role), lengths[6], is_nulls[6]);
    bindOutString(out[7], status, sizeof(status), lengths[7], is_nulls[7]);
    bindOutString(out[8], created_at, sizeof(created_at), lengths[8], is_nulls[8]);

    if (mysql_stmt_bind_result(stmt, out.data()) != 0) {
        throw std::runtime_error(std::string("MySQL bind_result failed: ") + mysql_stmt_error(stmt));
    }

    int rc = mysql_stmt_fetch(stmt);
    if (rc == MYSQL_NO_DATA) {
        return std::nullopt;
    }
    if (rc != 0 && rc != MYSQL_DATA_TRUNCATED) {
        throw std::runtime_error(std::string("MySQL fetch failed: ") + mysql_stmt_error(stmt));
    }

    UserRecord u;
    u.id = id;
    u.username = extractString(username, lengths[1], is_nulls[1], sizeof(username));
    u.password = extractString(password, lengths[2], is_nulls[2], sizeof(password));
    u.full_name = extractString(full_name, lengths[3], is_nulls[3], sizeof(full_name));
    u.email = extractString(email, lengths[4], is_nulls[4], sizeof(email));
    u.phone = extractString(phone, lengths[5], is_nulls[5], sizeof(phone));
    u.role = extractString(role, lengths[6], is_nulls[6], sizeof(role));
    u.status = extractString(status, lengths[7], is_nulls[7], sizeof(status));
    u.created_at = extractString(created_at, lengths[8], is_nulls[8], sizeof(created_at));
    return u;
}

std::optional<UserRecord> MysqlDatabase::createUser(const std::string& username,
                                                  const std::string& password_hash,
                                                  const std::string& full_name,
                                                  const std::string& email,
                                                  const std::string& phone,
                                                  const std::string& role,
                                                  std::string& error_out) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();

    const char* sql = R"SQL(
        INSERT INTO users (username, password, full_name, email, phone, role, status)
        VALUES (?, ?, ?, ?, ?, ?, 'active')
    )SQL";

    MysqlStmtGuard stmt(conn_, sql);
    std::array<MYSQL_BIND, 6> params{};
    std::array<unsigned long, 6> lens{};
    std::array<MysqlBool, 6> nulls{};

    bindStringParam(params[0], username, lens[0], nulls[0]);
    bindStringParam(params[1], password_hash, lens[1], nulls[1]);
    bindStringParam(params[2], full_name, lens[2], nulls[2]);
    bindNullableStringParam(params[3], email, lens[3], nulls[3]);
    bindNullableStringParam(params[4], phone, lens[4], nulls[4]);
    bindStringParam(params[5], role, lens[5], nulls[5]);

    if (mysql_stmt_bind_param(stmt.get(), params.data()) != 0) {
        error_out = mysql_stmt_error(stmt.get());
        return std::nullopt;
    }

    if (mysql_stmt_execute(stmt.get()) != 0) {
        unsigned int err_no = mysql_stmt_errno(stmt.get());
        if (err_no == ER_DUP_ENTRY) {
            error_out = "Username already exists";
        } else {
            error_out = mysql_stmt_error(stmt.get());
        }
        return std::nullopt;
    }

    int64_t new_id = static_cast<int64_t>(mysql_stmt_insert_id(stmt.get()));

    const char* select_sql =
        "SELECT id, username, password, full_name, email, phone, role, status, "
        "COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') "
        "FROM users WHERE id = ? LIMIT 1";
    MysqlStmtGuard select_stmt(conn_, select_sql);
    MYSQL_BIND id_param{};
    bindInt64Param(id_param, new_id);
    if (mysql_stmt_bind_param(select_stmt.get(), &id_param) != 0) {
        error_out = mysql_stmt_error(select_stmt.get());
        return std::nullopt;
    }
    return fetchSingleUserStmt(select_stmt.get());
}

std::optional<UserRecord> MysqlDatabase::findUserSingleStringLocked(const char* sql,
                                                                    const std::string& value) {
    ensureConnectedLocked();
    MysqlStmtGuard stmt(conn_, sql);
    MYSQL_BIND param{};
    unsigned long len = 0;
    MysqlBool is_null = 0;
    bindStringParam(param, value, len, is_null);
    if (mysql_stmt_bind_param(stmt.get(), &param) != 0) {
        throw std::runtime_error(std::string("MySQL bind_param failed: ") + mysql_stmt_error(stmt.get()));
    }
    return fetchSingleUserStmt(stmt.get());
}

std::optional<UserRecord> MysqlDatabase::findUserByEmail(const std::string& email) {
    std::lock_guard<std::mutex> lock(mutex_);
    return findUserSingleStringLocked(
        "SELECT id, username, password, full_name, email, phone, role, status, "
        "COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') "
        "FROM users WHERE LOWER(email) = LOWER(?) LIMIT 1",
        email);
}

std::optional<UserRecord> MysqlDatabase::findUserByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(mutex_);
    return findUserSingleStringLocked(
        "SELECT id, username, password, full_name, email, phone, role, status, "
        "COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') "
        "FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1",
        username);
}

std::optional<UserRecord> MysqlDatabase::findUserById(int64_t user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql =
        "SELECT id, username, password, full_name, email, phone, role, status, "
        "COALESCE(DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s'), '') "
        "FROM users WHERE id = ? LIMIT 1";
    MysqlStmtGuard stmt(conn_, sql);
    MYSQL_BIND param{};
    int64_t uid = user_id;
    bindInt64Param(param, uid);
    if (mysql_stmt_bind_param(stmt.get(), &param) != 0) {
        throw std::runtime_error(std::string("MySQL bind_param failed: ") + mysql_stmt_error(stmt.get()));
    }
    return fetchSingleUserStmt(stmt.get());
}

bool MysqlDatabase::updatePassword(int64_t user_id, const std::string& new_password_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql = "UPDATE users SET password = ? WHERE id = ?";
    MysqlStmtGuard stmt(conn_, sql);
    std::array<MYSQL_BIND, 2> params{};
    unsigned long len0 = 0;
    MysqlBool null0 = 0;
    int64_t uid = user_id;
    bindStringParam(params[0], new_password_hash, len0, null0);
    bindInt64Param(params[1], uid);

    if (mysql_stmt_bind_param(stmt.get(), params.data()) != 0) {
        return false;
    }
    if (mysql_stmt_execute(stmt.get()) != 0) {
        return false;
    }
    return mysql_stmt_affected_rows(stmt.get()) > 0;
}

bool MysqlDatabase::storeRefreshToken(int64_t user_id,
                                      const std::string& token_hash,
                                      int64_t expires_at,
                                      int64_t now_epoch_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql = R"SQL(
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at)
        VALUES (?, ?, ?, 0, ?)
    )SQL";
    MysqlStmtGuard stmt(conn_, sql);
    std::array<MYSQL_BIND, 4> params{};
    int64_t uid = user_id;
    int64_t exp = expires_at;
    int64_t now = now_epoch_sec;
    unsigned long len = 0;
    MysqlBool is_null = 0;

    bindInt64Param(params[0], uid);
    bindStringParam(params[1], token_hash, len, is_null);
    bindInt64Param(params[2], exp);
    bindInt64Param(params[3], now);

    if (mysql_stmt_bind_param(stmt.get(), params.data()) != 0) {
        return false;
    }
    return mysql_stmt_execute(stmt.get()) == 0;
}

std::optional<RefreshTokenRecord> MysqlDatabase::findRefreshToken(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql = R"SQL(
        SELECT id, user_id, token_hash, expires_at, revoked, created_at
        FROM refresh_tokens
        WHERE token_hash = ? LIMIT 1
    )SQL";
    MysqlStmtGuard stmt(conn_, sql);
    MYSQL_BIND param{};
    unsigned long len = 0;
    MysqlBool is_null = 0;
    bindStringParam(param, token_hash, len, is_null);
    if (mysql_stmt_bind_param(stmt.get(), &param) != 0) {
        throw std::runtime_error(std::string("MySQL bind_param failed: ") + mysql_stmt_error(stmt.get()));
    }
    if (mysql_stmt_execute(stmt.get()) != 0) {
        throw std::runtime_error(std::string("MySQL execute failed: ") + mysql_stmt_error(stmt.get()));
    }
    if (mysql_stmt_store_result(stmt.get()) != 0) {
        throw std::runtime_error(std::string("MySQL store_result failed: ") + mysql_stmt_error(stmt.get()));
    }

    int64_t id = 0;
    int64_t user_id = 0;
    char hash_buf[128]{};
    int64_t expires_at = 0;
    signed char revoked = 0;
    int64_t created_at = 0;

    std::array<unsigned long, 6> lengths{};
    std::array<MysqlBool, 6> is_nulls{};
    std::array<MYSQL_BIND, 6> out{};

    std::memset(out.data(), 0, sizeof(out));
    out[0].buffer_type = MYSQL_TYPE_LONGLONG;
    out[0].buffer = &id;
    out[0].is_null = &is_nulls[0];

    out[1].buffer_type = MYSQL_TYPE_LONGLONG;
    out[1].buffer = &user_id;
    out[1].is_null = &is_nulls[1];

    bindOutString(out[2], hash_buf, sizeof(hash_buf), lengths[2], is_nulls[2]);

    out[3].buffer_type = MYSQL_TYPE_LONGLONG;
    out[3].buffer = &expires_at;
    out[3].is_null = &is_nulls[3];

    out[4].buffer_type = MYSQL_TYPE_TINY;
    out[4].buffer = &revoked;
    out[4].is_null = &is_nulls[4];

    out[5].buffer_type = MYSQL_TYPE_LONGLONG;
    out[5].buffer = &created_at;
    out[5].is_null = &is_nulls[5];

    if (mysql_stmt_bind_result(stmt.get(), out.data()) != 0) {
        throw std::runtime_error(std::string("MySQL bind_result failed: ") + mysql_stmt_error(stmt.get()));
    }

    int rc = mysql_stmt_fetch(stmt.get());
    if (rc == MYSQL_NO_DATA) {
        return std::nullopt;
    }
    if (rc != 0 && rc != MYSQL_DATA_TRUNCATED) {
        throw std::runtime_error(std::string("MySQL fetch failed: ") + mysql_stmt_error(stmt.get()));
    }

    RefreshTokenRecord rec;
    rec.id = id;
    rec.user_id = user_id;
    rec.token_hash = extractString(hash_buf, lengths[2], is_nulls[2], sizeof(hash_buf));
    rec.expires_at = expires_at;
    rec.revoked = (revoked != 0);
    rec.created_at = created_at;
    return rec;
}

bool MysqlDatabase::revokeRefreshToken(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql = "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0";
    MysqlStmtGuard stmt(conn_, sql);
    MYSQL_BIND param{};
    unsigned long len = 0;
    MysqlBool is_null = 0;
    bindStringParam(param, token_hash, len, is_null);
    if (mysql_stmt_bind_param(stmt.get(), &param) != 0) {
        return false;
    }
    if (mysql_stmt_execute(stmt.get()) != 0) {
        return false;
    }
    return mysql_stmt_affected_rows(stmt.get()) > 0;
}

bool MysqlDatabase::revokeAllUserRefreshTokens(int64_t user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ensureConnectedLocked();
    const char* sql = "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0";
    MysqlStmtGuard stmt(conn_, sql);
    MYSQL_BIND param{};
    int64_t uid = user_id;
    bindInt64Param(param, uid);
    if (mysql_stmt_bind_param(stmt.get(), &param) != 0) {
        return false;
    }
    return mysql_stmt_execute(stmt.get()) == 0;
}

}  // namespace auth
