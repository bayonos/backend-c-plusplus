#include "crypto.hpp"

#include <crow/json.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace auth::crypto {

namespace {

constexpr char kBase64Alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::vector<std::string> split(const std::string& input, char delimiter) {
    std::vector<std::string> parts;
    std::stringstream ss(input);
    std::string item;
    while (std::getline(ss, item, delimiter)) {
        parts.push_back(item);
    }
    if (!input.empty() && input.back() == delimiter) {
        parts.emplace_back();
    }
    return parts;
}

}  // namespace

std::string toHex(const std::vector<uint8_t>& data) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(kHexDigits[(b >> 4) & 0x0F]);
        out.push_back(kHexDigits[b & 0x0F]);
    }
    return out;
}

std::optional<std::vector<uint8_t>> fromHex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        int hi = nibble(hex[i]);
        int lo = nibble(hex[i + 1]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::string base64UrlEncode(const std::vector<uint8_t>& data) {
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i < data.size()) {
        uint32_t octet_a = data[i++];
        uint32_t octet_b = (i < data.size()) ? data[i++] : 0;
        uint32_t octet_c = (i < data.size()) ? data[i++] : 0;
        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out.push_back(kBase64Alphabet[(triple >> 18) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 12) & 0x3F]);
        out.push_back(kBase64Alphabet[(triple >> 6) & 0x3F]);
        out.push_back(kBase64Alphabet[triple & 0x3F]);
    }

    size_t mod = data.size() % 3;
    if (mod == 1) {
        out.resize(out.size() - 2);
    } else if (mod == 2) {
        out.resize(out.size() - 1);
    }

    for (char& c : out) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    return out;
}

std::string base64UrlEncode(const std::string& data) {
    return base64UrlEncode(std::vector<uint8_t>(data.begin(), data.end()));
}

std::optional<std::string> base64UrlDecode(const std::string& encoded) {
    if (encoded.empty()) {
        return std::string();
    }
    std::string b64 = encoded;
    for (char& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4 != 0) {
        b64.push_back('=');
    }

    static const std::array<int, 256> kDecodeTable = [] {
        std::array<int, 256> table{};
        table.fill(-1);
        for (int i = 0; i < 64; ++i) {
            table[static_cast<unsigned char>(kBase64Alphabet[i])] = i;
        }
        return table;
    }();

    std::string out;
    out.reserve((b64.size() / 4) * 3);

    for (size_t i = 0; i < b64.size(); i += 4) {
        int vals[4];
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            char c = b64[i + j];
            if (c == '=') {
                vals[j] = 0;
                ++pad;
            } else {
                int v = kDecodeTable[static_cast<unsigned char>(c)];
                if (v < 0) return std::nullopt;
                vals[j] = v;
            }
        }
        if (pad > 2) return std::nullopt;
        uint32_t triple = (static_cast<uint32_t>(vals[0]) << 18) |
                          (static_cast<uint32_t>(vals[1]) << 12) |
                          (static_cast<uint32_t>(vals[2]) << 6) |
                          static_cast<uint32_t>(vals[3]);

        out.push_back(static_cast<char>((triple >> 16) & 0xFF));
        if (pad < 2) out.push_back(static_cast<char>((triple >> 8) & 0xFF));
        if (pad < 1) out.push_back(static_cast<char>(triple & 0xFF));
    }
    return out;
}

std::vector<uint8_t> randomBytes(size_t num_bytes) {
    std::vector<uint8_t> buf(num_bytes);
    if (num_bytes > 0 && RAND_bytes(buf.data(), static_cast<int>(num_bytes)) != 1) {
        throw std::runtime_error("OpenSSL RAND_bytes failed");
    }
    return buf;
}

std::string randomHex(size_t num_bytes) {
    return toHex(randomBytes(num_bytes));
}

std::string sha256Hex(const std::string& input) {
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
              EVP_DigestUpdate(ctx, input.data(), input.size()) == 1 &&
              EVP_DigestFinal_ex(ctx, digest.data(), &digest_len) == 1;
    EVP_MD_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("SHA-256 digest failed");
    }
    digest.resize(digest_len);
    return toHex(digest);
}

bool constantTimeEquals(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) {
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

std::string hashPassword(const std::string& password, int iterations) {
    constexpr size_t kSaltBytes = 16;
    constexpr size_t kKeyBytes = 32;

    std::vector<uint8_t> salt = randomBytes(kSaltBytes);
    std::vector<uint8_t> derived(kKeyBytes);

    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt.data(),
                          static_cast<int>(salt.size()),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(derived.size()),
                          derived.data()) != 1) {
        throw std::runtime_error("PKCS5_PBKDF2_HMAC failed");
    }

    return "pbkdf2_sha256$" + std::to_string(iterations) + "$" + toHex(salt) + "$" + toHex(derived);
}

bool verifyPassword(const std::string& password, const std::string& stored_hash) {
    auto parts = split(stored_hash, '$');
    if (parts.size() != 4 || parts[0] != "pbkdf2_sha256") {
        return false;
    }

    int iterations = 0;
    try {
        iterations = std::stoi(parts[1]);
    } catch (...) {
        return false;
    }
    if (iterations <= 0) {
        return false;
    }

    auto salt = fromHex(parts[2]);
    auto expected = fromHex(parts[3]);
    if (!salt || !expected || expected->empty()) {
        return false;
    }

    std::vector<uint8_t> derived(expected->size());
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt->data(),
                          static_cast<int>(salt->size()),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(derived.size()),
                          derived.data()) != 1) {
        return false;
    }

    return CRYPTO_memcmp(derived.data(), expected->data(), expected->size()) == 0;
}

std::string createJwt(const JwtClaims& claims, const std::string& secret) {
    crow::json::wvalue header;
    header["alg"] = "HS256";
    header["typ"] = "JWT";

    crow::json::wvalue payload;
    payload["sub"] = claims.user_id;
    payload["username"] = claims.username;
    payload["email"] = claims.email;
    payload["role"] = claims.role;
    payload["iat"] = claims.issued_at;
    payload["exp"] = claims.expires_at;
    payload["jti"] = claims.jti;

    std::string signing_input =
        base64UrlEncode(header.dump()) + "." + base64UrlEncode(payload.dump());

    std::vector<uint8_t> sig(EVP_MAX_MD_SIZE);
    unsigned int sig_len = 0;
    unsigned char* result = HMAC(EVP_sha256(),
                                 secret.data(),
                                 static_cast<int>(secret.size()),
                                 reinterpret_cast<const unsigned char*>(signing_input.data()),
                                 signing_input.size(),
                                 sig.data(),
                                 &sig_len);
    if (!result) {
        throw std::runtime_error("HMAC-SHA256 signing failed");
    }
    sig.resize(sig_len);

    return signing_input + "." + base64UrlEncode(sig);
}

std::optional<JwtClaims> verifyJwt(const std::string& token, const std::string& secret, int64_t now_epoch_sec) {
    auto parts = split(token, '.');
    if (parts.size() != 3) {
        return std::nullopt;
    }

    std::string signing_input = parts[0] + "." + parts[1];
    std::vector<uint8_t> expected_sig(EVP_MAX_MD_SIZE);
    unsigned int expected_len = 0;
    unsigned char* res = HMAC(EVP_sha256(),
                              secret.data(),
                              static_cast<int>(secret.size()),
                              reinterpret_cast<const unsigned char*>(signing_input.data()),
                              signing_input.size(),
                              expected_sig.data(),
                              &expected_len);
    if (!res) {
        return std::nullopt;
    }
    expected_sig.resize(expected_len);
    std::string expected_sig_b64 = base64UrlEncode(expected_sig);

    if (!constantTimeEquals(parts[2], expected_sig_b64)) {
        return std::nullopt;
    }

    auto header_json_str = base64UrlDecode(parts[0]);
    auto payload_json_str = base64UrlDecode(parts[1]);
    if (!header_json_str || !payload_json_str) {
        return std::nullopt;
    }

    auto header_json = crow::json::load(*header_json_str);
    auto payload_json = crow::json::load(*payload_json_str);
    if (!header_json || !payload_json) {
        return std::nullopt;
    }

    if (!header_json.has("alg") || header_json["alg"].s() != "HS256") {
        return std::nullopt;
    }

    if (!payload_json.has("sub") || !payload_json.has("exp") ||
        !payload_json.has("username") || !payload_json.has("email")) {
        return std::nullopt;
    }

    JwtClaims claims;
    try {
        claims.user_id = payload_json["sub"].i();
        claims.username = payload_json["username"].s();
        claims.email = payload_json["email"].s();
        claims.role = payload_json.has("role") ? std::string(payload_json["role"].s()) : "";
        claims.issued_at = payload_json.has("iat") ? payload_json["iat"].i() : 0;
        claims.expires_at = payload_json["exp"].i();
        claims.jti = payload_json.has("jti") ? std::string(payload_json["jti"].s()) : "";
    } catch (...) {
        return std::nullopt;
    }

    if (claims.user_id <= 0 || claims.expires_at <= now_epoch_sec) {
        return std::nullopt;
    }

    return claims;
}

}  // namespace auth::crypto
