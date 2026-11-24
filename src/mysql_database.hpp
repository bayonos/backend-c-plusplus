#pragma once

#include "database.hpp"

#include <mysql.h>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>

namespace auth {

class MysqlDatabase final : public IDatabase {
public:
    MysqlDatabase(std::string host,
                  uint16_t port,
                  std::string user,
                  std::string password,
                  std::string database);
    ~MysqlDatabase() override;

    MysqlDatabase(const MysqlDatabase&) = delete;
    MysqlDatabase& operator=(const MysqlDatabase&) = delete;

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
    std::string host_;
    uint16_t port_;
    std::string user_;
    std::string password_;
    std::string database_;

    MYSQL* conn_ = nullptr;
    std::mutex mutex_;

    void connectLocked();
    void ensureConnectedLocked();
    void execQueryLocked(const std::string& sql);
    std::optional<UserRecord> findUserSingleStringLocked(const char* sql, const std::string& value);
    std::optional<UserRecord> fetchSingleUserStmt(MYSQL_STMT* stmt);
};

}  // namespace auth
