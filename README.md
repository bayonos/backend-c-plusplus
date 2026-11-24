# C++ Login & Authentication Backend (`smartfarm_db` / MySQL)

A modular C++20 authentication HTTP API server powered by **Crow**, **OpenSSL 3**, and **MySQL 8.0** (`libmysqlclient`), mapped directly to the `smartfarm_db.users` table.

## MySQL Configuration

Default connection settings (configurable via environment variables):

- `DB_DRIVER=mysql`
- `MYSQL_HOST=127.0.0.1`
- `MYSQL_PORT=3306`
- `MYSQL_USER=root`
- `MYSQL_PASSWORD=root`
- `MYSQL_DB=smartfarm_db`

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
