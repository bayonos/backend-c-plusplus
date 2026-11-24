#pragma once

#include <cstdint>
#include <cstdlib>
#include <initializer_list>
#include <string>

namespace auth {

struct Config {
    std::string host = "0.0.0.0";
    uint16_t port = 8080;

    // Database backend: "mysql" (default) or "sqlite"
    std::string db_driver = "mysql";
    std::string db_path = "auth.db";  // Used when db_driver == "sqlite"

    std::string mysql_host = "127.0.0.1";
    uint16_t mysql_port = 3306;
    std::string mysql_user = "root";
    std::string mysql_password = "root";
    std::string mysql_database = "smartfarm_db";

    std::string jwt_secret;
    bool jwt_secret_is_ephemeral = false;
    int64_t access_token_ttl_sec = 900;       // 15 minutes
    int64_t refresh_token_ttl_sec = 604800;   // 7 days
    int pbkdf2_iterations = 210000;
    int max_login_attempts = 10;
    int64_t rate_limit_window_sec = 60;
    int threads = 4;

    static Config fromEnv();
    static void applyDatabaseUrl(const std::string& url, Config& cfg);
};

inline std::string getEnvOrDefault(const char* name, const std::string& fallback) {
    const char* val = std::getenv(name);
    if (val == nullptr || *val == '\0') {
        return fallback;
    }
    return std::string(val);
}

inline std::string getFirstEnvOrDefault(std::initializer_list<const char*> names,
                                        const std::string& fallback) {
    for (const char* name : names) {
        const char* val = std::getenv(name);
        if (val != nullptr && *val != '\0') {
            return std::string(val);
        }
    }
    return fallback;
}

inline int64_t getEnvInt64OrDefault(const char* name, int64_t fallback) {
    const char* val = std::getenv(name);
    if (val == nullptr || *val == '\0') {
        return fallback;
    }
    try {
        return std::stoll(val);
    } catch (...) {
        return fallback;
    }
}

inline int64_t getFirstEnvInt64OrDefault(std::initializer_list<const char*> names, int64_t fallback) {
    for (const char* name : names) {
        const char* val = std::getenv(name);
        if (val != nullptr && *val != '\0') {
            try {
                return std::stoll(val);
            } catch (...) {
            }
        }
    }
    return fallback;
}

}  // namespace auth
