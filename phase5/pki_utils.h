#pragma once

#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <iostream>

#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include "aes_utils.h"

namespace pki {

inline bool read_file(const std::string &filename, std::string &data) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) return false;
    std::ostringstream buffer;
    buffer << file.rdbuf();
    data = buffer.str();
    return true;
}

inline bool send_blob(int fd, const std::string &data) {
    uint32_t len_be = htonl(static_cast<uint32_t>(data.size()));
    if (!aesgcm::send_all(fd, reinterpret_cast<unsigned char *>(&len_be), sizeof(len_be))) return false;
    return data.empty() || aesgcm::send_all(fd,
        reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

inline bool recv_blob(int fd, std::string &data) {
    uint32_t len_be = 0;
    if (!aesgcm::recv_all(fd, reinterpret_cast<unsigned char *>(&len_be), sizeof(len_be))) return false;
    uint32_t len = ntohl(len_be);
    if (len == 0 || len > 1024 * 1024) return false;
    std::vector<unsigned char> buffer(len);
    if (!aesgcm::recv_all(fd, buffer.data(), buffer.size())) return false;
    data.assign(reinterpret_cast<const char *>(buffer.data()), buffer.size());
    return true;
}

inline X509 *load_certificate(const std::string &filename) {
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) return nullptr;
    X509 *cert = PEM_read_X509(file, nullptr, nullptr, nullptr);
    fclose(file);
    return cert;
}

inline EVP_PKEY *load_private_key(const std::string &filename) {
    FILE *file = fopen(filename.c_str(), "r");
    if (!file) return nullptr;
    EVP_PKEY *key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);
    return key;
}

inline std::string to_hex(const unsigned char *data, size_t len) {
    static const char *hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[(data[i] >> 4) & 0x0F]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

inline bool from_hex(const std::string &hex, std::vector<unsigned char> &out) {
    if (hex.empty() || hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int value = 0;
        if (sscanf(hex.substr(i, 2).c_str(), "%02x", &value) != 1) return false;
        out.push_back(static_cast<unsigned char>(value));
    }
    return true;
}

inline bool generate_challenge(std::string &challenge_hex) {
    unsigned char challenge[32];
    if (RAND_bytes(challenge, sizeof(challenge)) != 1) return false;
    challenge_hex = to_hex(challenge, sizeof(challenge));
    return true;
}

inline bool verify_certificate(X509 *server_cert,
                               const std::string &ca_file,
                               const std::string &expected_server_name) {
    X509 *ca_cert = load_certificate(ca_file);
    if (!ca_cert) return false;

    X509_STORE *store = X509_STORE_new();
    if (!store) { X509_free(ca_cert); return false; }

    bool ok = false;
    if (X509_STORE_add_cert(store, ca_cert) == 1) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (ctx && X509_STORE_CTX_init(ctx, store, server_cert, nullptr) == 1) {
            ok = (X509_verify_cert(ctx) == 1);
        }
        if (ctx) X509_STORE_CTX_free(ctx);
    }

    if (!ok) {
        std::cerr << "[PKI] Certificate signature or validity check failed.\n";
        X509_STORE_free(store);
        X509_free(ca_cert);
        return false;
    }

    X509_NAME *subject = X509_get_subject_name(server_cert);
    char cn[256] = {};
    int n = X509_NAME_get_text_by_NID(subject, NID_commonName, cn, sizeof(cn));
    if (n < 0 || expected_server_name != std::string(cn, n)) {
        std::cerr << "[PKI] Wrong server identity. Expected: "
                  << expected_server_name << ", received: "
                  << (n >= 0 ? std::string(cn, n) : "<missing>") << "\n";
        X509_STORE_free(store);
        X509_free(ca_cert);
        return false;
    }

    X509_STORE_free(store);
    X509_free(ca_cert);
    return true;
}

inline bool sign_data(EVP_PKEY *private_key,
                      const std::string &data,
                      std::vector<unsigned char> &signature) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    size_t len = 0;
    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, private_key) == 1 &&
        EVP_DigestSignUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestSignFinal(ctx, nullptr, &len) == 1) {
        signature.resize(len);
        if (EVP_DigestSignFinal(ctx, signature.data(), &len) == 1) {
            signature.resize(len);
            ok = true;
        }
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

inline bool verify_signature(X509 *certificate,
                             const std::string &data,
                             const std::vector<unsigned char> &signature) {
    EVP_PKEY *public_key = X509_get_pubkey(certificate);
    if (!public_key) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(public_key); return false; }
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, public_key) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data.data(), data.size()) == 1 &&
        EVP_DigestVerifyFinal(ctx, signature.data(), signature.size()) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    return ok;
}

} // namespace pki
