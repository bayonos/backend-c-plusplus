#pragma once

#include "auth_service.hpp"

#include <crow.h>
#include <crow/middlewares/cors.h>

namespace auth {

using HttpApp = crow::App<crow::CORSHandler>;

void registerRoutes(HttpApp& app, AuthService& auth_service);

}  // namespace auth
