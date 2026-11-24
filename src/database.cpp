#include "database.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace auth {

namespace {

class StmtGuard {
public:
    explicit StmtGuard(sqlite3* db, const char* sql) {
        if (sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr) != SQLITE_OK) {
            throw std::runtime_error(std::string("SQLite prepare failed: ") + sqlite3_errmsg(db));
        }
    }
    ~StmtGuard() {
        if (stmt_) {
            sqlite3_finalize(stmt_);
        }
    }
    StmtGuard(const StmtGuard&) = delete;
    StmtGuard& operator=(const StmtGuard&) = delete;

    sqlite3_stmt* get() const { return stmt_; }

private:
    sqlite3_stmt* stmt_ = nullptr;
};

std::string currentTimestampUtc() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm_utc{};
    gmtime_r(&t, &tm_utc);
    std::ostringstream oss;
    oss << std::put_time(&tm_utc, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string columnText(sqlite3_stmt* stmt, int col) {
    const unsigned char* txt = sqlite3_column_text(stmt, col);
    return txt ? reinterpret_cast<const char*>(txt) : "";
}

UserRecord readUserRow(sqlite3_stmt* stmt) {
    UserRecord u;
    u.id = sqlite3_column_int64(stmt, 0);
    u.username = columnText(stmt, 1);
    u.password = columnText(stmt, 2);
    u.full_name = columnText(stmt, 3);
    u.email = columnText(stmt, 4);
    u.phone = columnText(stmt, 5);
    u.role = columnText(stmt, 6);
    u.status = columnText(stmt, 7);
    u.created_at = columnText(stmt, 8);
    return u;
}

}  // namespace

SqliteDatabase::SqliteDatabase(const std::string& db_path) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "unknown error";
        if (db_) {
            sqlite3_close(db_);
            db_ = nullptr;
        }
        throw std::runtime_error("Failed to open SQLite database: " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);
    execSql("PRAGMA foreign_keys = ON;");
    execSql("PRAGMA journal_mode = WAL;");
}

SqliteDatabase::~SqliteDatabase() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

void SqliteDatabase::execSql(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQLite exec failed: " + msg);
    }
}

void SqliteDatabase::initSchema() {
    std::lock_guard<std::mutex> lock(mutex_);
    execSql(R"SQL(
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT COLLATE NOCASE,
            phone TEXT,
            role TEXT NOT NULL DEFAULT 'owner',
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
        CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
    )SQL");
}

std::optional<UserRecord> SqliteDatabase::createUser(const std::string& username,
                                                     const std::string& password_hash,
                                                     const std::string& full_name,
                                                     const std::string& email,
                                                     const std::string& phone,
                                                     const std::string& role,
                                                     std::string& error_out) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string created_at = currentTimestampUtc();
    const char* sql = R"SQL(
        INSERT INTO users (username, password, full_name, email, phone, role, status, created_at)
        VALUES (?, ?, ?, ?, ?, ?, 'active', ?);
    )SQL";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 2, password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 3, full_name.c_str(), -1, SQLITE_TRANSIENT);
    if (email.empty()) {
        sqlite3_bind_null(stmt.get(), 4);
    } else {
        sqlite3_bind_text(stmt.get(), 4, email.c_str(), -1, SQLITE_TRANSIENT);
    }
    if (phone.empty()) {
        sqlite3_bind_null(stmt.get(), 5);
    } else {
        sqlite3_bind_text(stmt.get(), 5, phone.c_str(), -1, SQLITE_TRANSIENT);
    }
    sqlite3_bind_text(stmt.get(), 6, role.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt.get(), 7, created_at.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_CONSTRAINT) {
        error_out = "Username already exists";
        return std::nullopt;
    }
    if (rc != SQLITE_DONE) {
        error_out = sqlite3_errmsg(db_);
        return std::nullopt;
    }

    UserRecord u;
    u.id = sqlite3_last_insert_rowid(db_);
    u.username = username;
    u.password = password_hash;
    u.full_name = full_name;
    u.email = email;
    u.phone = phone;
    u.role = role;
    u.status = "active";
    u.created_at = created_at;
    return u;
}

std::optional<UserRecord> SqliteDatabase::findUserByColumn(const char* sql, const std::string& value) {
    std::lock_guard<std::mutex> lock(mutex_);
    StmtGuard stmt(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, value.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return readUserRow(stmt.get());
    }
    return std::nullopt;
}

std::optional<UserRecord> SqliteDatabase::findUserByEmail(const std::string& email) {
    return findUserByColumn(
        "SELECT id, username, password, full_name, email, phone, role, status, created_at "
        "FROM users WHERE email = ? LIMIT 1;",
        email);
}

std::optional<UserRecord> SqliteDatabase::findUserByUsername(const std::string& username) {
    return findUserByColumn(
        "SELECT id, username, password, full_name, email, phone, role, status, created_at "
        "FROM users WHERE username = ? LIMIT 1;",
        username);
}

std::optional<UserRecord> SqliteDatabase::findUserById(int64_t user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql =
        "SELECT id, username, password, full_name, email, phone, role, status, created_at "
        "FROM users WHERE id = ?;";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_int64(stmt.get(), 1, user_id);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        return readUserRow(stmt.get());
    }
    return std::nullopt;
}

bool SqliteDatabase::updatePassword(int64_t user_id, const std::string& new_password_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql = "UPDATE users SET password = ? WHERE id = ?;";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, new_password_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 2, user_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool SqliteDatabase::storeRefreshToken(int64_t user_id,
                                       const std::string& token_hash,
                                       int64_t expires_at,
                                       int64_t now_epoch_sec) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql = R"SQL(
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, created_at)
        VALUES (?, ?, ?, 0, ?);
    )SQL";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_int64(stmt.get(), 1, user_id);
    sqlite3_bind_text(stmt.get(), 2, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt.get(), 3, expires_at);
    sqlite3_bind_int64(stmt.get(), 4, now_epoch_sec);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

std::optional<RefreshTokenRecord> SqliteDatabase::findRefreshToken(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql = R"SQL(
        SELECT id, user_id, token_hash, expires_at, revoked, created_at
        FROM refresh_tokens
        WHERE token_hash = ?;
    )SQL";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        RefreshTokenRecord rec;
        rec.id = sqlite3_column_int64(stmt.get(), 0);
        rec.user_id = sqlite3_column_int64(stmt.get(), 1);
        rec.token_hash = columnText(stmt.get(), 2);
        rec.expires_at = sqlite3_column_int64(stmt.get(), 3);
        rec.revoked = sqlite3_column_int(stmt.get(), 4) != 0;
        rec.created_at = sqlite3_column_int64(stmt.get(), 5);
        return rec;
    }
    return std::nullopt;
}

bool SqliteDatabase::revokeRefreshToken(const std::string& token_hash) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql = "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND revoked = 0;";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_text(stmt.get(), 1, token_hash.c_str(), -1, SQLITE_TRANSIENT);
    return sqlite3_step(stmt.get()) == SQLITE_DONE && sqlite3_changes(db_) > 0;
}

bool SqliteDatabase::revokeAllUserRefreshTokens(int64_t user_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const char* sql = "UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ? AND revoked = 0;";
    StmtGuard stmt(db_, sql);
    sqlite3_bind_int64(stmt.get(), 1, user_id);
    return sqlite3_step(stmt.get()) == SQLITE_DONE;
}

}  // namespace auth
