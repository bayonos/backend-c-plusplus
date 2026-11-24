#include "auth_service.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "database.hpp"
#include "http_server.hpp"

#include <crow.h>

#include <cassert>
#include <cstdlib>
#include <iostream>
#include <string>

namespace {

auth::Config makeTestConfig() {
    auth::Config cfg;
    cfg.db_driver = "sqlite";
    cfg.db_path = ":memory:";
    cfg.jwt_secret = "test-super-secret-key-at-least-32-bytes";
    cfg.access_token_ttl_sec = 900;
    cfg.refresh_token_ttl_sec = 3600;
    cfg.pbkdf2_iterations = 10000;
    cfg.max_login_attempts = 3;
    cfg.rate_limit_window_sec = 60;
    return cfg;
}

void testCrypto() {
    std::string raw = "hello+world/test=123";
    std::string b64 = auth::crypto::base64UrlEncode(raw);
    auto decoded = auth::crypto::base64UrlDecode(b64);
    assert(decoded.has_value());
    assert(*decoded == raw);

    std::string pw_hash = auth::crypto::hashPassword("SecretPass123", 10000);
    assert(pw_hash.rfind("pbkdf2_sha256$10000$", 0) == 0);
    assert(auth::crypto::verifyPassword("SecretPass123", pw_hash));
    assert(!auth::crypto::verifyPassword("WrongPass123", pw_hash));
    assert(!auth::crypto::verifyPassword("SecretPass123", "malformed"));

    int64_t now = auth::AuthService::nowEpochSeconds();
    auth::JwtClaims claims{42, "alice", "alice@example.com", "owner", now, now + 300, "jti-1"};
    std::string token = auth::crypto::createJwt(claims, "secret-key");

    auto verified = auth::crypto::verifyJwt(token, "secret-key", now);
    assert(verified.has_value());
    assert(verified->user_id == 42);
    assert(verified->username == "alice");
    assert(verified->email == "alice@example.com");
    assert(verified->role == "owner");

    assert(!auth::crypto::verifyJwt(token, "wrong-secret", now).has_value());
    assert(!auth::crypto::verifyJwt(token, "secret-key", now + 301).has_value());

    std::string tampered = token;
    tampered.back() = (tampered.back() == 'a') ? 'b' : 'a';
    assert(!auth::crypto::verifyJwt(tampered, "secret-key", now).has_value());

    std::cout << "[PASS] testCrypto\n";
}

void testRegisterLoginRefreshLogout() {
    auth::Config cfg = makeTestConfig();
    auth::SqliteDatabase db(cfg.db_path);
    db.initSchema();
    auth::AuthService service(db, cfg);

    // Invalid inputs
    assert(service.registerUser("ab", "Password123", "Alice", "a@example.com").status_code == 400);
    assert(service.registerUser("alice", "Password123", "", "a@example.com").status_code == 400);
    assert(service.registerUser("alice", "Password123", "Alice", "bad-email").status_code == 400);
    assert(service.registerUser("alice", "short1", "Alice", "alice@example.com").status_code == 400);
    assert(service.registerUser("alice", "onlyletters", "Alice", "alice@example.com").status_code == 400);
    assert(service.registerUser("alice", "Password123", "Alice", "alice@example.com", "", "invalidrole").status_code == 400);

    // Valid registration
    auto reg = service.registerUser("alice", "Password123", "Alice Chan", "Alice@Example.com", "010290240", "manager");
    assert(reg.ok && reg.status_code == 201);
    assert(reg.user.has_value());
    assert(reg.user->email == "alice@example.com");
    assert(reg.user->full_name == "Alice Chan");
    assert(reg.user->phone == "010290240");
    assert(reg.user->role == "manager");
    assert(reg.user->status == "active");
    assert(reg.tokens.has_value());

    // Duplicate email / username
    assert(service.registerUser("alice2", "Password123", "Alice Two", "alice@example.com").status_code == 409);
    assert(service.registerUser("ALICE", "Password123", "Alice Dup", "alice2@example.com").status_code == 409);

    // Authenticate access token
    auto claims = service.authenticateAccessToken(reg.tokens->access_token);
    assert(claims.has_value());
    assert(claims->user_id == reg.user->id);
    assert(claims->role == "manager");

    auto profile = service.getProfile(claims->user_id);
    assert(profile.ok && profile.user->username == "alice");

    // Login by email and by username
    auto login_email = service.login("ALICE@example.com", "Password123", "127.0.0.1");
    assert(login_email.ok && login_email.status_code == 200);

    auto login_user = service.login("alice", "Password123", "127.0.0.2");
    assert(login_user.ok && login_user.status_code == 200);

    // Wrong password
    auto bad_login = service.login("alice@example.com", "WrongPass123", "127.0.0.3");
    assert(!bad_login.ok && bad_login.status_code == 401);

    // Refresh token rotation
    std::string old_refresh = login_email.tokens->refresh_token;
    auto refreshed = service.refreshSession(old_refresh);
    assert(refreshed.ok && refreshed.status_code == 200);
    assert(refreshed.tokens->refresh_token != old_refresh);

    // Reusing old refresh token must fail
    auto reuse = service.refreshSession(old_refresh);
    assert(!reuse.ok && reuse.status_code == 401);

    // Logout revokes new refresh token
    auto out = service.logout(refreshed.tokens->refresh_token);
    assert(out.ok);
    assert(!service.refreshSession(refreshed.tokens->refresh_token).ok);

    std::cout << "[PASS] testRegisterLoginRefreshLogout\n";
}

void testLegacyPlaintextAndRateLimit() {
    auth::Config cfg = makeTestConfig();
    auth::SqliteDatabase db(cfg.db_path);
    db.initSchema();
    auth::AuthService service(db, cfg);

    // Simulate an existing smartfarm_db seed user with plaintext password
    std::string err;
    auto seeded = db.createUser("admin", "admin123", "Raksmey Chann", "admin@efarm.local", "010290240", "owner", err);
    assert(seeded.has_value());

    auto login_seed = service.login("admin", "admin123", "10.0.0.1");
    assert(login_seed.ok && login_seed.status_code == 200);
    assert(login_seed.user->full_name == "Raksmey Chann");
    assert(login_seed.user->role == "owner");

    // Rate limit threshold is 3 attempts per IP in test config
    assert(service.login("admin", "Wrong1", "10.0.0.5").status_code == 401);
    assert(service.login("admin", "Wrong2", "10.0.0.5").status_code == 401);
    assert(service.login("admin", "Wrong3", "10.0.0.5").status_code == 401);
    assert(service.login("admin", "admin123", "10.0.0.5").status_code == 429);

    // Change password revokes all existing refresh tokens
    std::string rt = login_seed.tokens->refresh_token;
    assert(service.changePassword(seeded->id, "WrongCurrent1", "NewPass123").status_code == 401);
    auto changed = service.changePassword(seeded->id, "admin123", "NewPass123");
    assert(changed.ok && changed.status_code == 200);

    assert(!service.refreshSession(rt).ok);
    assert(service.login("admin", "admin123", "10.0.0.6").status_code == 401);
    assert(service.login("admin", "NewPass123", "10.0.0.6").status_code == 200);

    std::cout << "[PASS] testLegacyPlaintextAndRateLimit\n";
}

crow::response dispatchRequest(auth::HttpApp& app,
                               crow::HTTPMethod method,
                               const std::string& url,
                               const std::string& body = "",
                               const std::string& auth_header = "") {
    crow::request req;
    req.method = method;
    req.url = url;
    req.body = body;
    req.remote_ip_address = "127.0.0.1";
    if (!auth_header.empty()) {
        req.add_header("Authorization", auth_header);
    }
    crow::response res;
    app.handle_full(req, res);
    return res;
}

void testHttpRoutes() {
    auth::Config cfg = makeTestConfig();
    auth::SqliteDatabase db(cfg.db_path);
    db.initSchema();
    auth::AuthService service(db, cfg);

    auth::HttpApp app;
    app.loglevel(crow::LogLevel::Critical);
    auth::registerRoutes(app, service);
    app.validate();

    // Root and Health
    auto root = dispatchRequest(app, crow::HTTPMethod::GET, "/");
    assert(root.code == 200);
    auto root_json = crow::json::load(root.body);
    assert(root_json && root_json["status"].s() == "ok");

    auto health = dispatchRequest(app, crow::HTTPMethod::GET, "/health");
    assert(health.code == 200);
    auto health_json = crow::json::load(health.body);
    assert(health_json && health_json["status"].s() == "ok");

    // Invalid JSON -> 400
    auto bad_json = dispatchRequest(app, crow::HTTPMethod::POST, "/api/auth/register", "{bad");
    assert(bad_json.code == 400);

    // Register
    auto reg = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/register",
        R"({"username":"httpuser","password":"Password123","full_name":"HTTP User","email":"http@example.com","phone":"012345678","role":"staff"})");
    assert(reg.code == 201);
    auto reg_json = crow::json::load(reg.body);
    assert(reg_json && reg_json.has("access_token") && reg_json.has("refresh_token"));
    assert(reg_json["user"]["full_name"].s() == "HTTP User");
    assert(reg_json["user"]["role"].s() == "staff");

    // Login (also verify /auth/login alias)
    auto login_alias = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/auth/login",
        R"({"email":"http@example.com","password":"Password123"})");
    assert(login_alias.code == 200);

    auto login = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/login",
        R"({"email":"http@example.com","password":"Password123"})");
    assert(login.code == 200);
    auto login_json = crow::json::load(login.body);
    std::string access_token = login_json["access_token"].s();
    std::string refresh_token = login_json["refresh_token"].s();

    // Protected /me without header -> 401
    auto me_unauth = dispatchRequest(app, crow::HTTPMethod::GET, "/api/auth/me");
    assert(me_unauth.code == 401);

    // Protected /me with Bearer token -> 200
    auto me = dispatchRequest(
        app, crow::HTTPMethod::GET, "/api/auth/me", "", "Bearer " + access_token);
    assert(me.code == 200);
    auto me_json = crow::json::load(me.body);
    assert(me_json["user"]["username"].s() == "httpuser");

    // Refresh
    auto ref = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/refresh",
        std::string(R"({"refresh_token":")") + refresh_token + R"("})");
    assert(ref.code == 200);
    auto ref_json = crow::json::load(ref.body);
    std::string new_refresh = ref_json["refresh_token"].s();
    assert(new_refresh != refresh_token);

    // Change password
    auto cp = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/change-password",
        R"({"current_password":"Password123","new_password":"NewPassword456"})",
        "Bearer " + access_token);
    assert(cp.code == 200);

    // Refresh token was revoked by password change -> 401
    auto ref_after_cp = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/refresh",
        std::string(R"({"refresh_token":")") + new_refresh + R"("})");
    assert(ref_after_cp.code == 401);

    // Login with new password & logout-all
    auto login2 = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/login",
        R"({"username":"httpuser","password":"NewPassword456"})");
    assert(login2.code == 200);
    auto login2_json = crow::json::load(login2.body);
    std::string access2 = login2_json["access_token"].s();
    std::string refresh2 = login2_json["refresh_token"].s();

    auto logout_all = dispatchRequest(
        app, crow::HTTPMethod::POST, "/api/auth/logout-all", "", "Bearer " + access2);
    assert(logout_all.code == 200);

    auto ref_after_logout_all = dispatchRequest(
        app,
        crow::HTTPMethod::POST,
        "/api/auth/refresh",
        std::string(R"({"refresh_token":")") + refresh2 + R"("})");
    assert(ref_after_logout_all.code == 401);

    std::cout << "[PASS] testHttpRoutes\n";
}

void testConfigEnvParsing() {
    auth::Config cfg;
    auth::Config::applyDatabaseUrl(
        "mysql://smartuser:pass%40word@bayonos-db-smartfarm:3307/smartfarm_db?ssl-mode=PREFERRED",
        cfg);
    assert(cfg.db_driver == "mysql");
    assert(cfg.mysql_user == "smartuser");
    assert(cfg.mysql_password == "pass@word");
    assert(cfg.mysql_host == "bayonos-db-smartfarm");
    assert(cfg.mysql_port == 3307);
    assert(cfg.mysql_database == "smartfarm_db");

    setenv("DB_CONNECTION", "mysql", 1);
    setenv("DB_HOST", "db.internal", 1);
    setenv("DB_PORT", "3308", 1);
    setenv("DB_USERNAME", "appuser", 1);
    setenv("DB_PASSWORD", "appsecret", 1);
    setenv("DB_DATABASE", "smartfarm_db", 1);

    auth::Config env_cfg = auth::Config::fromEnv();
    assert(env_cfg.db_driver == "mysql");
    assert(env_cfg.mysql_host == "db.internal");
    assert(env_cfg.mysql_port == 3308);
    assert(env_cfg.mysql_user == "appuser");
    assert(env_cfg.mysql_password == "appsecret");
    assert(env_cfg.mysql_database == "smartfarm_db");

    unsetenv("DB_CONNECTION");
    unsetenv("DB_HOST");
    unsetenv("DB_PORT");
    unsetenv("DB_USERNAME");
    unsetenv("DB_PASSWORD");
    unsetenv("DB_DATABASE");

    std::cout << "[PASS] testConfigEnvParsing\n";
}

}  // namespace

int main() {
    testConfigEnvParsing();
    testCrypto();
    testRegisterLoginRefreshLogout();
    testLegacyPlaintextAndRateLimit();
    testHttpRoutes();
    std::cout << "All unit tests passed.\n";
    return 0;
}
