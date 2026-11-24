#include "http_server.hpp"

#include <optional>
#include <string>

namespace auth {

namespace {

crow::response jsonResponse(int status_code, crow::json::wvalue body) {
    crow::response res(status_code, body.dump());
    res.set_header("Content-Type", "application/json");
    res.set_header("Cache-Control", "no-store");
    res.set_header("X-Content-Type-Options", "nosniff");
    return res;
}

crow::response errorResponse(int status_code, const std::string& message) {
    crow::json::wvalue body;
    body["error"] = message;
    return jsonResponse(status_code, std::move(body));
}

crow::json::wvalue userToJson(const PublicUser& u) {
    crow::json::wvalue j;
    j["id"] = u.id;
    j["username"] = u.username;
    j["full_name"] = u.full_name;
    j["email"] = u.email;
    j["phone"] = u.phone;
    j["role"] = u.role;
    j["status"] = u.status;
    j["created_at"] = u.created_at;
    return j;
}

crow::response authResultToResponse(const AuthResult& result) {
    if (!result.ok) {
        return errorResponse(result.status_code, result.error);
    }
    crow::json::wvalue body;
    if (result.user) {
        body["user"] = userToJson(*result.user);
    }
    if (result.tokens) {
        body["access_token"] = result.tokens->access_token;
        body["refresh_token"] = result.tokens->refresh_token;
        body["token_type"] = result.tokens->token_type;
        body["expires_in"] = result.tokens->expires_in;
    }
    return jsonResponse(result.status_code, std::move(body));
}

std::optional<std::string> extractBearerToken(const crow::request& req) {
    const std::string& header = req.get_header_value("Authorization");
    constexpr std::string_view kPrefix = "Bearer ";
    if (header.size() <= kPrefix.size() || header.compare(0, kPrefix.size(), kPrefix) != 0) {
        return std::nullopt;
    }
    std::string token = header.substr(kPrefix.size());
    if (token.empty()) {
        return std::nullopt;
    }
    return token;
}

std::optional<std::string> getStringField(const crow::json::rvalue& json, const char* key) {
    if (!json.has(key) || json[key].t() != crow::json::type::String) {
        return std::nullopt;
    }
    return std::string(json[key].s());
}

}  // namespace

void registerRoutes(HttpApp& app, AuthService& auth_service) {
    auto& cors = app.get_middleware<crow::CORSHandler>();
    cors.global()
        .origin("*")
        .methods(crow::HTTPMethod::GET, crow::HTTPMethod::POST, crow::HTTPMethod::OPTIONS)
        .headers("Content-Type", "Authorization");
    CROW_ROUTE(app, "/health").methods(crow::HTTPMethod::GET)([]() {
        crow::json::wvalue body;
        body["status"] = "ok";
        return jsonResponse(200, std::move(body));
    });

    CROW_ROUTE(app, "/api/auth/register")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body || body.t() != crow::json::type::Object) {
                return errorResponse(400, "Invalid JSON request body");
            }
            auto username = getStringField(body, "username");
            auto password = getStringField(body, "password");
            if (!username || !password) {
                return errorResponse(400, "username and password are required strings");
            }
            std::string full_name = getStringField(body, "full_name").value_or(*username);
            std::string email = getStringField(body, "email").value_or("");
            std::string phone = getStringField(body, "phone").value_or("");
            std::string role = getStringField(body, "role").value_or("owner");

            return authResultToResponse(
                auth_service.registerUser(*username, *password, full_name, email, phone, role));
        });

    CROW_ROUTE(app, "/api/auth/login")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body || body.t() != crow::json::type::Object) {
                return errorResponse(400, "Invalid JSON request body");
            }
            std::optional<std::string> identifier = getStringField(body, "identifier");
            if (!identifier) identifier = getStringField(body, "email");
            if (!identifier) identifier = getStringField(body, "username");
            auto password = getStringField(body, "password");
            if (!identifier || !password) {
                return errorResponse(400, "username (or email/identifier) and password are required");
            }
            return authResultToResponse(
                auth_service.login(*identifier, *password, req.remote_ip_address));
        });

    CROW_ROUTE(app, "/api/auth/refresh")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body || body.t() != crow::json::type::Object) {
                return errorResponse(400, "Invalid JSON request body");
            }
            auto refresh_token = getStringField(body, "refresh_token");
            if (!refresh_token) {
                return errorResponse(400, "refresh_token is required");
            }
            return authResultToResponse(auth_service.refreshSession(*refresh_token));
        });

    CROW_ROUTE(app, "/api/auth/logout")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto body = crow::json::load(req.body);
            if (!body || body.t() != crow::json::type::Object) {
                return errorResponse(400, "Invalid JSON request body");
            }
            auto refresh_token = getStringField(body, "refresh_token");
            if (!refresh_token) {
                return errorResponse(400, "refresh_token is required");
            }
            auto res = auth_service.logout(*refresh_token);
            if (!res.ok) {
                return errorResponse(res.status_code, res.error);
            }
            crow::json::wvalue out;
            out["message"] = "Logged out";
            return jsonResponse(200, std::move(out));
        });

    CROW_ROUTE(app, "/api/auth/logout-all")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto token = extractBearerToken(req);
            if (!token) {
                return errorResponse(401, "Missing or invalid Authorization header");
            }
            auto claims = auth_service.authenticateAccessToken(*token);
            if (!claims) {
                return errorResponse(401, "Invalid or expired access token");
            }
            auth_service.logoutAll(claims->user_id);
            crow::json::wvalue out;
            out["message"] = "All sessions revoked";
            return jsonResponse(200, std::move(out));
        });

    CROW_ROUTE(app, "/api/auth/me")
        .methods(crow::HTTPMethod::GET)([&auth_service](const crow::request& req) {
            auto token = extractBearerToken(req);
            if (!token) {
                return errorResponse(401, "Missing or invalid Authorization header");
            }
            auto claims = auth_service.authenticateAccessToken(*token);
            if (!claims) {
                return errorResponse(401, "Invalid or expired access token");
            }
            return authResultToResponse(auth_service.getProfile(claims->user_id));
        });

    CROW_ROUTE(app, "/api/auth/change-password")
        .methods(crow::HTTPMethod::POST)([&auth_service](const crow::request& req) {
            auto token = extractBearerToken(req);
            if (!token) {
                return errorResponse(401, "Missing or invalid Authorization header");
            }
            auto claims = auth_service.authenticateAccessToken(*token);
            if (!claims) {
                return errorResponse(401, "Invalid or expired access token");
            }
            auto body = crow::json::load(req.body);
            if (!body || body.t() != crow::json::type::Object) {
                return errorResponse(400, "Invalid JSON request body");
            }
            auto current_password = getStringField(body, "current_password");
            auto new_password = getStringField(body, "new_password");
            if (!current_password || !new_password) {
                return errorResponse(400, "current_password and new_password are required");
            }
            auto res = auth_service.changePassword(claims->user_id, *current_password, *new_password);
            if (!res.ok) {
                return errorResponse(res.status_code, res.error);
            }
            crow::json::wvalue out;
            out["message"] = "Password updated; all refresh tokens revoked";
            return jsonResponse(200, std::move(out));
        });
}

}  // namespace auth
