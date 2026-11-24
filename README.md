# C++ Login & Authentication Backend (`smartfarm_db` / MySQL)

A modular C++20 authentication HTTP API server powered by **Crow**, **OpenSSL 3**, and **MySQL 8.0** (`libmysqlclient`), mapped directly to the `smartfarm_db.users` table.

## MySQL Configuration

Supported environment variables (in priority order, with local defaults):

- `DATABASE_URL` (e.g., `mysql://user:password@host:3306/smartfarm_db`)
- `DB_DRIVER` or `DB_CONNECTION` (default `mysql`)
- `MYSQL_HOST` or `DB_HOST` (default `127.0.0.1`)
- `MYSQL_PORT` or `DB_PORT` (default `3306`)
- `MYSQL_USER` or `DB_USER` or `DB_USERNAME` (default `root`)
- `MYSQL_PASSWORD` or `DB_PASSWORD` (default `root`)
- `MYSQL_DB` or `DB_DATABASE` or `DB_NAME` (default `smartfarm_db`)

### `users` Table Mapping

Matches `smartfarm_db.users`:
`id`, `username`, `password`, `full_name`, `email`, `phone`, `role`, `status`, `created_at`.

- New users created via `POST /api/auth/register` or passwords updated via `POST /api/auth/change-password` are hashed with **PBKDF2-HMAC-SHA256** (`210,000` iterations, 16-byte CSPRNG salt).
- Existing legacy plaintext seed passwords in `smartfarm_db.users` (such as `admin` / `dara`) are also supported during login using constant-time verification.
- Accounts with `status != 'active'` are rejected with `403`.
- Refresh tokens are stored hashed (`SHA-256`) in `smartfarm_db.refresh_tokens` (created automatically on startup).

## Build & Run

```bash
make
JWT_SECRET="replace-with-a-long-random-secret" ./bin/auth_server
```

## Run Tests

```bash
make test
bash scripts/smoke_test.sh
```

## API Endpoints

- `GET /health`
- `POST /api/auth/register` — `{ "username", "password", "full_name", "email"?, "phone"?, "role"? }`
- `POST /api/auth/login` — `{ "username" | "email" | "identifier", "password" }`
- `POST /api/auth/refresh` — `{ "refresh_token" }`
- `POST /api/auth/logout` — `{ "refresh_token" }`
- `POST /api/auth/logout-all` — `Authorization: Bearer <access_token>`
- `GET /api/auth/me` — `Authorization: Bearer <access_token>`
- `POST /api/auth/change-password` — `Authorization: Bearer <access_token>`, `{ "current_password", "new_password" }`
