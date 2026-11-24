#include "auth_service.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <regex>

namespace auth {

RateLimiter::RateLimiter(int max_attempts, int64_t window_sec)
    : max_attempts_(max_attempts), window_sec_(window_sec) {}

bool RateLimiter::allow(const std::string& key, int64_t now_epoch_sec) {
    if (max_attempts_ <= 0 || window_sec_ <= 0) {
        return true;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto& q = attempts_[key];
    int64_t cutoff = now_epoch_sec - window_sec_;
    while (!q.empty() && q.front() <= cutoff) {
        q.pop_front();
    }
    if (static_cast<int>(q.size()) >= max_attempts_) {
        return false;
    }
    q.push_back(now_epoch_sec);
    return true;
}

AuthService::AuthService(IDatabase& db, Config config)
    : db_(db),
      config_(std::move(config)),
      login_limiter_(config_.max_login_attempts, config_.rate_limit_window_sec),
      dummy_hash_(crypto::hashPassword("timing-mitigation-placeholder", config_.pbkdf2_iterations)) {}

int64_t AuthService::nowEpochSeconds() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string AuthService::trim(const std::string& s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string AuthService::normalizeLowerTrim(const std::string& s) {
    std::string out = trim(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

bool AuthService::isValidUsername(const std::string& username) {
    if (username.size() < 3 || username.size() > 50) {
        return false;
    }
    static const std::regex kUsernameRegex("^[A-Za-z0-9_.-]+$");
    return std::regex_match(username, kUsernameRegex);
}

bool AuthService::isValidEmail(const std::string& email) {
    if (email.size() < 5 || email.size() > 120) {
        return false;
    }
    static const std::regex kEmailRegex(R"(^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$)");
    return std::regex_match(email, kEmailRegex);
}

bool AuthService::isValidRole(const std::string& role) {
    return role == "owner" || role == "manager" || role == "staff" || role == "admin";
}

std::optional<std::string> AuthService::validatePassword(const std::string& password) {
    if (password.size() < 8) {
        return "Password must be at least 8 characters long";
    }
    if (password.size() > 128) {
        return "Password must be at most 128 characters long";
    }
    bool has_letter = false;
    bool has_digit = false;
    for (unsigned char c : password) {
        if (std::isalpha(c)) has_letter = true;
        if (std::isdigit(c)) has_digit = true;
    }
    if (!has_letter || !has_digit) {
        return "Password must include at least one letter and one number";
    }
    return std::nullopt;
}

bool AuthService::verifyStoredPassword(const std::string& candidate, const std::string& stored) {
    if (stored.rfind("pbkdf2_sha256$", 0) == 0) {
        return crypto::verifyPassword(candidate, stored);
    }
    // Support legacy plaintext passwords already present in smartfarm_db.users.
    return !stored.empty() && crypto::constantTimeEquals(candidate, stored);
}

PublicUser AuthService::toPublicUser(const UserRecord& user) {
    return PublicUser{
        user.id,
        user.username,
        user.full_name,
        user.email,
        user.phone,
        user.role,
        user.status,
        user.created_at,
    };
}

AuthTokens AuthService::issueTokensForUser(const UserRecord& user, int64_t now_epoch_sec) {
    JwtClaims claims;
    claims.user_id = user.id;
    claims.username = user.username;
    claims.email = user.email;
    claims.role = user.role;
    claims.issued_at = now_epoch_sec;
    claims.expires_at = now_epoch_sec + config_.access_token_ttl_sec;
    claims.jti = crypto::randomHex(16);

    AuthTokens tokens;
    tokens.access_token = crypto::createJwt(claims, config_.jwt_secret);
    tokens.refresh_token = crypto::randomHex(32);
    tokens.token_type = "Bearer";
    tokens.expires_in = config_.access_token_ttl_sec;

    std::string refresh_hash = crypto::sha256Hex(tokens.refresh_token);
    if (!db_.storeRefreshToken(user.id,
                               refresh_hash,
                               now_epoch_sec + config_.refresh_token_ttl_sec,
                               now_epoch_sec)) {
        throw std::runtime_error("Failed to store refresh token");
    }
    return tokens;
}

AuthResult AuthService::registerUser(const std::string& username,
                                     const std::string& password,
                                     const std::string& full_name,
                                     const std::string& email,
                                     const std::string& phone,
                                     const std::string& role) {
    std::string clean_username = trim(username);
    std::string clean_full_name = trim(full_name);
    std::string clean_email = normalizeLowerTrim(email);
    std::string clean_phone = trim(phone);
    std::string clean_role = role.empty() ? "owner" : normalizeLowerTrim(role);

    if (!isValidUsername(clean_username)) {
        return {false, 400, "Username must be 3-50 characters (letters, digits, _, ., -)", std::nullopt, std::nullopt};
    }
    if (clean_full_name.empty() || clean_full_name.size() > 100) {
        return {false, 400, "full_name is required (max 100 characters)", std::nullopt, std::nullopt};
    }
    if (!clean_email.empty() && !isValidEmail(clean_email)) {
        return {false, 400, "Invalid email address", std::nullopt, std::nullopt};
    }
    if (clean_phone.size() > 30) {
        return {false, 400, "phone must be at most 30 characters", std::nullopt, std::nullopt};
    }
    if (!isValidRole(clean_role)) {
        return {false, 400, "role must be one of: owner, manager, staff, admin", std::nullopt, std::nullopt};
    }
    if (auto pw_err = validatePassword(password)) {
        return {false, 400, *pw_err, std::nullopt, std::nullopt};
    }

    if (!clean_email.empty() && db_.findUserByEmail(clean_email)) {
        return {false, 409, "Email already exists", std::nullopt, std::nullopt};
    }

    int64_t now = nowEpochSeconds();
    std::string password_hash = crypto::hashPassword(password, config_.pbkdf2_iterations);

    std::string db_error;
    auto created = db_.createUser(
        clean_username, password_hash, clean_full_name, clean_email, clean_phone, clean_role, db_error);
    if (!created) {
        return {false, 409, db_error, std::nullopt, std::nullopt};
    }

    AuthTokens tokens = issueTokensForUser(*created, now);
    return {true, 201, "", toPublicUser(*created), tokens};
}

AuthResult AuthService::login(const std::string& identifier,
                              const std::string& password,
                              const std::string& client_ip) {
    int64_t now = nowEpochSeconds();
    std::string rate_key = client_ip.empty() ? "unknown" : client_ip;
    if (!login_limiter_.allow(rate_key, now)) {
        return {false, 429, "Too many login attempts. Please try again later.", std::nullopt, std::nullopt};
    }

    std::string clean_id = trim(identifier);
    if (clean_id.empty() || password.empty()) {
        return {false, 400, "Identifier and password are required", std::nullopt, std::nullopt};
    }

    std::optional<UserRecord> user;
    if (clean_id.find('@') != std::string::npos) {
        user = db_.findUserByEmail(normalizeLowerTrim(clean_id));
    } else {
        user = db_.findUserByUsername(clean_id);
    }

    if (!user) {
        crypto::verifyPassword(password, dummy_hash_);
        return {false, 401, "Invalid credentials", std::nullopt, std::nullopt};
    }

    if (!verifyStoredPassword(password, user->password)) {
        return {false, 401, "Invalid credentials", std::nullopt, std::nullopt};
    }

    if (user->status != "active") {
        return {false, 403, "User account is inactive", std::nullopt, std::nullopt};
    }

    AuthTokens tokens = issueTokensForUser(*user, now);
    return {true, 200, "", toPublicUser(*user), tokens};
}

AuthResult AuthService::refreshSession(const std::string& refresh_token) {
    std::string clean_token = trim(refresh_token);
    if (clean_token.empty()) {
        return {false, 400, "refresh_token is required", std::nullopt, std::nullopt};
    }

    int64_t now = nowEpochSeconds();
    std::string token_hash = crypto::sha256Hex(clean_token);
    auto record = db_.findRefreshToken(token_hash);
    if (!record || record->revoked || record->expires_at <= now) {
        return {false, 401, "Invalid or expired refresh token", std::nullopt, std::nullopt};
    }

    if (!db_.revokeRefreshToken(token_hash)) {
        return {false, 401, "Invalid or expired refresh token", std::nullopt, std::nullopt};
    }

    auto user = db_.findUserById(record->user_id);
    if (!user) {
        return {false, 401, "User no longer exists", std::nullopt, std::nullopt};
    }
    if (user->status != "active") {
        return {false, 403, "User account is inactive", std::nullopt, std::nullopt};
    }

    AuthTokens tokens = issueTokensForUser(*user, now);
    return {true, 200, "", toPublicUser(*user), tokens};
}

AuthResult AuthService::logout(const std::string& refresh_token) {
    std::string clean_token = trim(refresh_token);
    if (clean_token.empty()) {
        return {false, 400, "refresh_token is required", std::nullopt, std::nullopt};
    }
    std::string token_hash = crypto::sha256Hex(clean_token);
    db_.revokeRefreshToken(token_hash);
    return {true, 200, "", std::nullopt, std::nullopt};
}

AuthResult AuthService::logoutAll(int64_t user_id) {
    db_.revokeAllUserRefreshTokens(user_id);
    return {true, 200, "", std::nullopt, std::nullopt};
}

std::optional<JwtClaims> AuthService::authenticateAccessToken(const std::string& bearer_token) const {
    if (bearer_token.empty()) {
        return std::nullopt;
    }
    return crypto::verifyJwt(bearer_token, config_.jwt_secret, nowEpochSeconds());
}

AuthResult AuthService::getProfile(int64_t user_id) {
    auto user = db_.findUserById(user_id);
    if (!user) {
        return {false, 404, "User not found", std::nullopt, std::nullopt};
    }
    return {true, 200, "", toPublicUser(*user), std::nullopt};
}

AuthResult AuthService::changePassword(int64_t user_id,
                                       const std::string& current_password,
                                       const std::string& new_password) {
    if (current_password.empty() || new_password.empty()) {
        return {false, 400, "current_password and new_password are required", std::nullopt, std::nullopt};
    }
    if (auto pw_err = validatePassword(new_password)) {
        return {false, 400, *pw_err, std::nullopt, std::nullopt};
    }

    auto user = db_.findUserById(user_id);
    if (!user) {
        return {false, 404, "User not found", std::nullopt, std::nullopt};
    }

    if (!verifyStoredPassword(current_password, user->password)) {
        return {false, 401, "Current password is incorrect", std::nullopt, std::nullopt};
    }

    std::string new_hash = crypto::hashPassword(new_password, config_.pbkdf2_iterations);
    if (!db_.updatePassword(user_id, new_hash)) {
        return {false, 500, "Failed to update password", std::nullopt, std::nullopt};
    }

    db_.revokeAllUserRefreshTokens(user_id);
    return {true, 200, "", std::nullopt, std::nullopt};
}

}  // namespace auth
