#include "auth_service.hpp"
#include "config.hpp"
#include "database.hpp"
#include "http_server.hpp"
#include "mysql_database.hpp"

#include <crow.h>

#include <iostream>
#include <memory>

int main() {
    try {
        auth::Config cfg = auth::Config::fromEnv();
        if (cfg.jwt_secret_is_ephemeral) {
            std::cerr << "[WARN] JWT_SECRET is not set; generated an ephemeral secret for this process.\n";
        }

        std::unique_ptr<auth::IDatabase> db;
        std::string db_desc;
        if (cfg.db_driver == "sqlite") {
            db = std::make_unique<auth::SqliteDatabase>(cfg.db_path);
            db_desc = "sqlite:" + cfg.db_path;
        } else if (cfg.db_driver == "mysql") {
            db = std::make_unique<auth::MysqlDatabase>(
                cfg.mysql_host, cfg.mysql_port, cfg.mysql_user, cfg.mysql_password, cfg.mysql_database);
            db_desc = "mysql://" + cfg.mysql_user + "@" + cfg.mysql_host + ":" +
                      std::to_string(cfg.mysql_port) + "/" + cfg.mysql_database;
        } else {
            throw std::runtime_error("Unsupported DB_DRIVER: " + cfg.db_driver + " (expected mysql or sqlite)");
        }

        db->initSchema();

        auth::AuthService auth_service(*db, cfg);

        auth::HttpApp app;
        app.loglevel(crow::LogLevel::Warning);
        auth::registerRoutes(app, auth_service);

        std::cout << "Auth server listening on http://" << cfg.host << ":" << cfg.port
                  << " (db=" << db_desc << ", threads=" << cfg.threads << ")\n";

        app.bindaddr(cfg.host)
            .port(cfg.port)
            .concurrency(static_cast<uint16_t>(cfg.threads))
            .run();
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "Fatal error: " << ex.what() << "\n";
        return 1;
    }
}
