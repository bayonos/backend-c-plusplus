#include "config.hpp"
#include "crypto.hpp"

#include <algorithm>
#include <cctype>

namespace auth {

namespace {

std::string urlDecode(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    auto hexVal = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '%' && i + 2 < in.size()) {
            int hi = hexVal(in[i + 1]);
            int lo = hexVal(in[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        out.push_back(in[i]);
    }
    return out;
}

}  // namespace

void Config::applyDatabaseUrl(const std::string& url, Config& cfg) {
    if (url.empty()) {
        return;
    }
    size_t scheme_end = url.find("://");
    if (scheme_end == std::string::npos) {
        return;
    }
    std::string scheme = url.substr(0, scheme_end);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    std::string rest = url.substr(scheme_end + 3);

    if (scheme == "sqlite" || scheme == "sqlite3") {
        cfg.db_driver = "sqlite";
        if (!rest.empty()) {
            cfg.db_path = rest;
        }
        return;
    }

    if (scheme != "mysql" && scheme != "mysql2" && scheme != "mariadb") {
        return;
    }
    cfg.db_driver = "mysql";

    // Strip optional query string (?ssl-mode=...)
    size_t q_pos = rest.find('?');
    if (q_pos != std::string::npos) {
        rest = rest.substr(0, q_pos);
    }

    std::string authority = rest;
    std::string db_name;
    size_t slash_pos = rest.find('/');
    if (slash_pos != std::string::npos) {
        authority = rest.substr(0, slash_pos);
        db_name = rest.substr(slash_pos + 1);
    }
    if (!db_name.empty()) {
        cfg.mysql_database = urlDecode(db_name);
    }

    std::string host_port = authority;
    size_t at_pos = authority.rfind('@');
    if (at_pos != std::string::npos) {
        std::string userinfo = authority.substr(0, at_pos);
        host_port = authority.substr(at_pos + 1);
        size_t colon_pos = userinfo.find(':');
        if (colon_pos != std::string::npos) {
            cfg.mysql_user = urlDecode(userinfo.substr(0, colon_pos));
            cfg.mysql_password = urlDecode(userinfo.substr(colon_pos + 1));
        } else if (!userinfo.empty()) {
            cfg.mysql_user = urlDecode(userinfo);
        }
    }

    if (!host_port.empty()) {
        size_t colon_pos = host_port.rfind(':');
        if (colon_pos != std::string::npos) {
            std::string host_part = host_port.substr(0, colon_pos);
            std::string port_part = host_port.substr(colon_pos + 1);
            if (!host_part.empty()) {
                cfg.mysql_host = host_part;
            }
            try {
                int64_t p = std::stoll(port_part);
                if (p > 0 && p <= 65535) {
                    cfg.mysql_port = static_cast<uint16_t>(p);
                }
            } catch (...) {
            }
        } else {
            cfg.mysql_host = host_port;
        }
    }
}

Config Config::fromEnv() {
    Config cfg;
    cfg.host = getEnvOrDefault("HOST", "0.0.0.0");

    int64_t parsed_port = getEnvInt64OrDefault("PORT", 8080);
    if (parsed_port > 0 && parsed_port <= 65535) {
        cfg.port = static_cast<uint16_t>(parsed_port);
    }

    // 1. Parse DATABASE_URL if provided.
    std::string database_url = getEnvOrDefault("DATABASE_URL", "");
    if (!database_url.empty()) {
        applyDatabaseUrl(database_url, cfg);
    }

    // 2. Allow explicit MYSQL_* or DB_* environment variables to set/override values.
    cfg.db_driver = getFirstEnvOrDefault({"DB_DRIVER", "DB_CONNECTION"}, cfg.db_driver);
    cfg.db_path = getEnvOrDefault("DB_PATH", cfg.db_path);

    cfg.mysql_host = getFirstEnvOrDefault({"MYSQL_HOST", "DB_HOST"}, cfg.mysql_host);
    int64_t parsed_mysql_port =
        getFirstEnvInt64OrDefault({"MYSQL_PORT", "DB_PORT"}, static_cast<int64_t>(cfg.mysql_port));
    if (parsed_mysql_port > 0 && parsed_mysql_port <= 65535) {
        cfg.mysql_port = static_cast<uint16_t>(parsed_mysql_port);
    }
    cfg.mysql_user = getFirstEnvOrDefault({"MYSQL_USER", "DB_USER", "DB_USERNAME"}, cfg.mysql_user);
    cfg.mysql_password = getFirstEnvOrDefault({"MYSQL_PASSWORD", "DB_PASSWORD"}, cfg.mysql_password);
    cfg.mysql_database =
        getFirstEnvOrDefault({"MYSQL_DB", "DB_DATABASE", "DB_NAME"}, cfg.mysql_database);

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
