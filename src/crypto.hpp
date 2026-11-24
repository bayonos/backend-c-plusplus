#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace auth {

struct JwtClaims {
    int64_t user_id = 0;
    std::string username;
    std::string email;
    std::string role;
    int64_t issued_at = 0;
    int64_t expires_at = 0;
    std::string jti;
};

namespace crypto {

std::string toHex(const std::vector<uint8_t>& data);
std::optional<std::vector<uint8_t>> fromHex(const std::string& hex);

std::string base64UrlEncode(const std::vector<uint8_t>& data);
std::string base64UrlEncode(const std::string& data);
std::optional<std::string> base64UrlDecode(const std::string& encoded);

std::vector<uint8_t> randomBytes(size_t num_bytes);
std::string randomHex(size_t num_bytes);
std::string sha256Hex(const std::string& input);

bool constantTimeEquals(const std::string& a, const std::string& b);

// Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
std::string hashPassword(const std::string& password, int iterations = 210000);
bool verifyPassword(const std::string& password, const std::string& stored_hash);

std::string createJwt(const JwtClaims& claims, const std::string& secret);
std::optional<JwtClaims> verifyJwt(const std::string& token, const std::string& secret, int64_t now_epoch_sec);

}  // namespace crypto
}  // namespace auth
