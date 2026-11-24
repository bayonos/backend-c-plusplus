#pragma once

#include "config.hpp"
#include "crypto.hpp"
#include "database.hpp"

#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace auth {

struct PublicUser {
    int64_t id = 0;
    std::string username;
    std::string full_name;
    std::string email;
    std::string phone;
    std::string role;
    std::string status;
    std::string created_at;
};

struct AuthTokens {
    std::string access_token;
    std::string refresh_token;
    std::string token_type = "Bearer";
    int64_t expires_in = 0;
};

struct AuthResult {
    bool ok = false;
    int status_code = 200;
    std::string error;
    std::optional<PublicUser> user;
    std::optional<AuthTokens> tokens;
};

class RateLimiter {
public:
    RateLimiter(int max_attempts, int64_t window_sec);
    bool allow(const std::string& key, int64_t now_epoch_sec);

private:
    int max_attempts_;
    int64_t window_sec_;
    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<int64_t>> attempts_;
};

class AuthService {
public:
    AuthService(IDatabase& db, Config config);

    AuthResult registerUser(const std::string& username,
                            const std::string& password,
                            const std::string& full_name,
                            const std::string& email = "",
                            const std::string& phone = "",
                            const std::string& role = "owner");

    AuthResult login(const std::string& identifier,
                     const std::string& password,
                     const std::string& client_ip);

    AuthResult refreshSession(const std::string& refresh_token);

    AuthResult logout(const std::string& refresh_token);

    AuthResult logoutAll(int64_t user_id);

    std::optional<JwtClaims> authenticateAccessToken(const std::string& bearer_token) const;

    AuthResult getProfile(int64_t user_id);

    AuthResult changePassword(int64_t user_id,
                              const std::string& current_password,
                              const std::string& new_password);

    static int64_t nowEpochSeconds();

private:
    IDatabase& db_;
    Config config_;
    RateLimiter login_limiter_;
    std::string dummy_hash_;

    AuthTokens issueTokensForUser(const UserRecord& user, int64_t now_epoch_sec);
    static bool verifyStoredPassword(const std::string& candidate, const std::string& stored);
    static PublicUser toPublicUser(const UserRecord& user);
    static std::string normalizeLowerTrim(const std::string& s);
    static std::string trim(const std::string& s);
    static bool isValidUsername(const std::string& username);
    static bool isValidEmail(const std::string& email);
    static bool isValidRole(const std::string& role);
    static std::optional<std::string> validatePassword(const std::string& password);
};

}  // namespace auth
