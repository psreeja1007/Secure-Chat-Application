#pragma once

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace aesgcm {

constexpr int KEY_LEN = 32;
constexpr int NONCE_LEN = 12;
constexpr int TAG_LEN = 16;

using Key = std::array<unsigned char, KEY_LEN>;

inline std::vector<unsigned char> encrypt(const Key &key, const std::string &plaintext) {
    std::vector<unsigned char> nonce(NONCE_LEN);
    if (RAND_bytes(nonce.data(), NONCE_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed for GCM nonce");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    unsigned char tag[TAG_LEN];
    int output_length = 0;
    int total_length = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (!plaintext.empty()) {
        if (EVP_EncryptUpdate(ctx, ciphertext.data(), &output_length,
                              reinterpret_cast<const unsigned char *>(plaintext.data()),
                              static_cast<int>(plaintext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        total_length = output_length;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_length, &output_length) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total_length += output_length;
    ciphertext.resize(static_cast<size_t>(total_length));

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CIPHER_CTX_ctrl GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    std::vector<unsigned char> encrypted_blob;
    encrypted_blob.reserve(static_cast<size_t>(NONCE_LEN + ciphertext.size() + TAG_LEN));
    encrypted_blob.insert(encrypted_blob.end(), nonce.begin(), nonce.end());
    encrypted_blob.insert(encrypted_blob.end(), ciphertext.begin(), ciphertext.end());
    encrypted_blob.insert(encrypted_blob.end(), tag, tag + TAG_LEN);
    return encrypted_blob;
}

inline bool decrypt(const Key &key, const std::vector<unsigned char> &blob, std::string &plaintext_out) {
    if (blob.size() < static_cast<size_t>(NONCE_LEN + TAG_LEN)) {
        return false;
    }

    const unsigned char *nonce = blob.data();
    const unsigned char *ciphertext = blob.data() + NONCE_LEN;
    size_t ciphertext_length = blob.size() - NONCE_LEN - TAG_LEN;
    const unsigned char *tag = blob.data() + NONCE_LEN + ciphertext_length;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<unsigned char> plaintext(ciphertext_length);
    int output_length = 0;
    int total_length = 0;
    bool ok = true;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) {
        ok = false;
    }

    if (ok && ciphertext_length > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &output_length,
                              ciphertext, static_cast<int>(ciphertext_length)) != 1) {
            ok = false;
        } else {
            total_length = output_length;
        }
    }

    if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                  const_cast<unsigned char *>(tag)) != 1) {
        ok = false;
    }

    if (ok) {
        int final_length = 0;
        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total_length, &final_length) != 1) {
            ok = false;
        } else {
            total_length += final_length;
        }
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return false;
    }

    plaintext.resize(static_cast<size_t>(total_length));
    plaintext_out.assign(plaintext.begin(), plaintext.end());
    return true;
}

inline bool send_all(int sock_fd, const unsigned char *data, size_t length) {
    size_t sent = 0;
    while (sent < length) {
        ssize_t bytes_sent = send(sock_fd, data + sent, length - sent, 0);
        if (bytes_sent <= 0) {
            return false;
        }
        sent += static_cast<size_t>(bytes_sent);
    }
    return true;
}

inline bool recv_all(int sock_fd, unsigned char *data, size_t length) {
    size_t received = 0;
    while (received < length) {
        ssize_t bytes_received = recv(sock_fd, data + received, length - received, 0);
        if (bytes_received <= 0) {
            return false;
        }
        received += static_cast<size_t>(bytes_received);
    }
    return true;
}

inline bool send_encrypted(int sock_fd, const Key &key, const std::string &plaintext) {
    std::vector<unsigned char> encrypted_blob = encrypt(key, plaintext);
    uint32_t message_length = htonl(static_cast<uint32_t>(encrypted_blob.size()));
    if (!send_all(sock_fd, reinterpret_cast<unsigned char *>(&message_length), sizeof(message_length))) {
        return false;
    }
    return send_all(sock_fd, encrypted_blob.data(), encrypted_blob.size());
}

enum class RecvStatus { OK, DISCONNECTED, AUTH_FAILED, ERROR };

inline RecvStatus recv_encrypted(int sock_fd, const Key &key, std::string &plaintext_out) {
    uint32_t length_bytes = 0;
    ssize_t received = recv(sock_fd, &length_bytes, sizeof(length_bytes), MSG_WAITALL);
    if (received == 0) return RecvStatus::DISCONNECTED;
    if (received != sizeof(length_bytes)) return RecvStatus::ERROR;

    uint32_t length = ntohl(length_bytes);
    constexpr uint32_t MAX_BLOB_SIZE = 16 * 1024 * 1024;
    if (length < static_cast<uint32_t>(NONCE_LEN + TAG_LEN) || length > MAX_BLOB_SIZE) {
        return RecvStatus::ERROR;
    }

    std::vector<unsigned char> encrypted_blob(length);
    if (!recv_all(sock_fd, encrypted_blob.data(), encrypted_blob.size())) {
        return RecvStatus::DISCONNECTED;
    }

    if (!decrypt(key, encrypted_blob, plaintext_out)) {
        return RecvStatus::AUTH_FAILED;
    }

    return RecvStatus::OK;
}

} // namespace aesgcm
