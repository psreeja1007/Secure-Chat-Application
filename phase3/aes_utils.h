#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>

namespace aesgcm {

constexpr int KEY_LEN = 32;
constexpr int NONCE_LEN = 12;
constexpr int TAG_LEN = 16;

using Key = std::array<unsigned char, KEY_LEN>;

inline std::vector<unsigned char> encrypt(const Key &key, const std::string &plaintext) {
    std::vector<unsigned char> nonce(NONCE_LEN);
    if (RAND_bytes(nonce.data(), NONCE_LEN) != 1)
        throw std::runtime_error("RAND_bytes failed for GCM nonce");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> ciphertext(plaintext.size());
    unsigned char tag[TAG_LEN];
    int out_len = 0;
    int total_len = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                              reinterpret_cast<const unsigned char *>(plaintext.data()),
                              static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        total_len = out_len;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total_len += out_len;
    ciphertext.resize(static_cast<size_t>(total_len));

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> blob;
    blob.reserve(static_cast<size_t>(NONCE_LEN + ciphertext.size() + TAG_LEN));
    blob.insert(blob.end(), nonce.begin(), nonce.end());
    blob.insert(blob.end(), ciphertext.begin(), ciphertext.end());
    blob.insert(blob.end(), tag, tag + TAG_LEN);
    return blob;
}

inline bool decrypt(const Key &key, const std::vector<unsigned char> &blob, std::string &plaintext_out) {
    if (blob.size() < static_cast<size_t>(NONCE_LEN + TAG_LEN)) {
        return false;
    }

    const unsigned char *nonce = blob.data();
    const unsigned char *ciphertext = blob.data() + NONCE_LEN;
    size_t ct_len = blob.size() - NONCE_LEN - TAG_LEN;
    const unsigned char *tag = blob.data() + NONCE_LEN + ct_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<unsigned char> plaintext(ct_len);
    int out_len = 0;
    int total_len = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
        ok = false;
    }

    if (ok && ct_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                              ciphertext, static_cast<int>(ct_len)) != 1) {
            ok = false;
        } else {
            total_len = out_len;
        }
    }

    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                  const_cast<unsigned char *>(tag)) != 1) {
        ok = false;
    }

    if (ok) {
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len, &final_len) != 1) {
            ok = false;
        } else {
            total_len += final_len;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;

    plaintext.resize(static_cast<size_t>(total_len));
    plaintext_out.assign(plaintext.begin(), plaintext.end());
    return true;
}

inline bool send_all(int sock_fd, const unsigned char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock_fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool recv_all(int sock_fd, unsigned char *data, size_t len) {
    size_t received = 0;
    while (received < len) {
        ssize_t n = recv(sock_fd, data + received, len - received, 0);
        if (n <= 0) return false;
        received += static_cast<size_t>(n);
    }
    return true;
}

inline bool send_encrypted(int sock_fd, const Key &key, const std::string &plaintext) {
    std::vector<unsigned char> blob = encrypt(key, plaintext);
    uint32_t len_be = htonl(static_cast<uint32_t>(blob.size()));
    if (!send_all(sock_fd, reinterpret_cast<unsigned char *>(&len_be), sizeof(len_be)))
        return false;
    return send_all(sock_fd, blob.data(), blob.size());
}

enum class RecvStatus { OK, DISCONNECTED, AUTH_FAILED, ERROR };

inline RecvStatus recv_encrypted(int sock_fd, const Key &key, std::string &plaintext_out) {
    uint32_t len_be = 0;
    ssize_t n = recv(sock_fd, &len_be, sizeof(len_be), MSG_WAITALL);
    if (n == 0) return RecvStatus::DISCONNECTED;
    if (n != sizeof(len_be)) return RecvStatus::ERROR;

    uint32_t len = ntohl(len_be);
    constexpr uint32_t MAX_BLOB = 16 * 1024 * 1024;
    if (len < static_cast<uint32_t>(NONCE_LEN + TAG_LEN) || len > MAX_BLOB)
        return RecvStatus::ERROR;

    std::vector<unsigned char> blob(len);
    if (!recv_all(sock_fd, blob.data(), blob.size()))
        return RecvStatus::DISCONNECTED;

    if (!decrypt(key, blob, plaintext_out))
        return RecvStatus::AUTH_FAILED;

    return RecvStatus::OK;
}

} // namespace aesgcm
