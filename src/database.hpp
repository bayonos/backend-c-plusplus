#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace auth {

struct UserRecord {
    int64_t id = 0;
    std::string username;
    std::string password;
    std::string full_name;
    std::string email;
    std::string phone;
    std::string role = "owner";
    std::string status = "active";
    std::string created_at;
};

struct RefreshTokenRecord {
    int64_t id = 0;
    int64_t user_id = 0;
    std::string token_hash;
    int64_t expires_at = 0;
    bool revoked = false;
    int64_t created_at = 0;
};

class IDatabase {
public:
    virtual ~IDatabase() = default;

    virtual void initSchema() = 0;

    virtual std::optional<UserRecord> createUser(const std::string& username,
                                                 const std::string& password_hash,
                                                 const std::string& full_name,
                                                 const std::string& email,
                                                 const std::string& phone,
                                                 const std::string& role,
                                                 std::string& error_out) = 0;

    virtual std::optional<UserRecord> findUserByEmail(const std::string& email) = 0;
    virtual std::optional<UserRecord> findUserByUsername(const std::string& username) = 0;
    virtual std::optional<UserRecord> findUserById(int64_t user_id) = 0;
    virtual bool updatePassword(int64_t user_id, const std::string& new_password_hash) = 0;

    virtual bool storeRefreshToken(int64_t user_id,
                                   const std::string& token_hash,
                                   int64_t expires_at,
                                   int64_t now_epoch_sec) = 0;
    virtual std::optional<RefreshTokenRecord> findRefreshToken(const std::string& token_hash) = 0;
    virtual bool revokeRefreshToken(const std::string& token_hash) = 0;
    virtual bool revokeAllUserRefreshTokens(int64_t user_id) = 0;
};

class SqliteDatabase final : public IDatabase {
public:
    explicit SqliteDatabase(const std::string& db_path);
    ~SqliteDatabase() override;

    SqliteDatabase(const SqliteDatabase&) = delete;
    SqliteDatabase& operator=(const SqliteDatabase&) = delete;

    void initSchema() override;

    std::optional<UserRecord> createUser(const std::string& username,
                                         const std::string& password_hash,
                                         const std::string& full_name,
                                         const std::string& email,
                                         const std::string& phone,
                                         const std::string& role,
                                         std::string& error_out) override;

    std::optional<UserRecord> findUserByEmail(const std::string& email) override;
    std::optional<UserRecord> findUserByUsername(const std::string& username) override;
    std::optional<UserRecord> findUserById(int64_t user_id) override;
    bool updatePassword(int64_t user_id, const std::string& new_password_hash) override;

    bool storeRefreshToken(int64_t user_id,
                           const std::string& token_hash,
                           int64_t expires_at,
                           int64_t now_epoch_sec) override;
    std::optional<RefreshTokenRecord> findRefreshToken(const std::string& token_hash) override;
    bool revokeRefreshToken(const std::string& token_hash) override;
    bool revokeAllUserRefreshTokens(int64_t user_id) override;

private:
    sqlite3* db_ = nullptr;
    std::mutex mutex_;

    void execSql(const std::string& sql);
    std::optional<UserRecord> findUserByColumn(const char* sql, const std::string& value);
};

}  // namespace auth
