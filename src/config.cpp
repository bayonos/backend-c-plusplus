#include "config.hpp"
#include "crypto.hpp"

#include <algorithm>

namespace auth {

Config Config::fromEnv() {
    Config cfg;
    cfg.host = getEnvOrDefault("HOST", "0.0.0.0");

    int64_t parsed_port = getEnvInt64OrDefault("PORT", 8080);
    if (parsed_port > 0 && parsed_port <= 65535) {
        cfg.port = static_cast<uint16_t>(parsed_port);
    }

    cfg.db_driver = getEnvOrDefault("DB_DRIVER", "mysql");
    cfg.db_path = getEnvOrDefault("DB_PATH", "auth.db");

    cfg.mysql_host = getEnvOrDefault("MYSQL_HOST", "127.0.0.1");
    int64_t parsed_mysql_port = getEnvInt64OrDefault("MYSQL_PORT", 3306);
    if (parsed_mysql_port > 0 && parsed_mysql_port <= 65535) {
        cfg.mysql_port = static_cast<uint16_t>(parsed_mysql_port);
    }
    cfg.mysql_user = getEnvOrDefault("MYSQL_USER", "root");
    cfg.mysql_password = getEnvOrDefault("MYSQL_PASSWORD", "root");
    cfg.mysql_database = getEnvOrDefault("MYSQL_DB", "smartfarm_db");

    cfg.jwt_secret = getEnvOrDefault("JWT_SECRET", "");
    if (cfg.jwt_secret.empty()) {
        cfg.jwt_secret = crypto::randomHex(32);
        cfg.jwt_secret_is_ephemeral = true;
    }

    int64_t access_ttl = getEnvInt64OrDefault("ACCESS_TOKEN_TTL_SEC", 900);
    if (access_ttl > 0) cfg.access_token_ttl_sec = access_ttl;

    int64_t refresh_ttl = getEnvInt64OrDefault("REFRESH_TOKEN_TTL_SEC", 604800);
    if (refresh_ttl > 0) cfg.refresh_token_ttl_sec = refresh_ttl;

    int64_t iterations = getEnvInt64OrDefault("PBKDF2_ITERATIONS", 210000);
    if (iterations >= 10000) cfg.pbkdf2_iterations = static_cast<int>(iterations);

    int64_t max_attempts = getEnvInt64OrDefault("LOGIN_MAX_ATTEMPTS", 10);
    if (max_attempts > 0) cfg.max_login_attempts = static_cast<int>(max_attempts);

    int64_t rate_window = getEnvInt64OrDefault("LOGIN_RATE_WINDOW_SEC", 60);
    if (rate_window > 0) cfg.rate_limit_window_sec = rate_window;

    int64_t threads = getEnvInt64OrDefault("THREADS", 4);
    cfg.threads = static_cast<int>(std::clamp<int64_t>(threads, 1, 64));

    return cfg;
}

}  // namespace auth
