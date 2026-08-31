// dh_utils.h
//
// Diffie-Hellman helpers.
// The code uses RFC 3526 Group 14 and derives an AES-256 key with SHA-256.
#pragma once

#include <openssl/bn.h>
#include <openssl/sha.h>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace dh {

inline const char *GROUP14_PRIME_HEX_CANONICAL =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";

inline const char *GROUP14_GENERATOR_DEC = "2";

struct KeyPair {
    BIGNUM *p = nullptr;
    BIGNUM *g = nullptr;
    BIGNUM *priv = nullptr;
    BIGNUM *pub = nullptr;
};

inline void free_keypair(KeyPair &kp) {
    if (kp.p) BN_clear_free(kp.p);
    if (kp.g) BN_free(kp.g);
    if (kp.priv) BN_clear_free(kp.priv);
    if (kp.pub) BN_free(kp.pub);
    kp = KeyPair{};
}

inline std::string bn_to_hex(const BIGNUM *bn) {
    char *tmp = BN_bn2hex(bn);
    if (!tmp) return "";
    std::string result(tmp);
    OPENSSL_free(tmp);
    return result;
}

inline bool hex_to_bn(BIGNUM **bn, const std::string &hex) {
    if (hex.empty()) return false;
    return BN_hex2bn(bn, hex.c_str()) != 0;
}

inline BIGNUM *mod_pow(const BIGNUM *base, const BIGNUM *exp, const BIGNUM *mod, BN_CTX *ctx) {
    if (!base || !exp || !mod) {
        throw std::runtime_error("mod_pow received a null input");
    }

    BIGNUM *result = BN_new();
    BIGNUM *current_base = BN_new();
    BIGNUM *current_exp = BN_new();
    BIGNUM *temp = BN_new();

    if (!result || !current_base || !current_exp || !temp) {
        BN_free(result);
        BN_free(current_base);
        BN_free(current_exp);
        BN_free(temp);
        throw std::runtime_error("mod_pow allocation failed");
    }

    if (!BN_one(result)) {
        BN_free(result);
        BN_free(current_base);
        BN_free(current_exp);
        BN_free(temp);
        throw std::runtime_error("BN_one failed in mod_pow");
    }

    if (!BN_copy(current_base, base) || !BN_copy(current_exp, exp)) {
        BN_free(result);
        BN_free(current_base);
        BN_free(current_exp);
        BN_free(temp);
        throw std::runtime_error("BN_copy failed in mod_pow");
    }

    if (!BN_mod(current_base, current_base, mod, ctx)) {
        BN_free(result);
        BN_free(current_base);
        BN_free(current_exp);
        BN_free(temp);
        throw std::runtime_error("BN_mod failed in mod_pow");
    }

    while (!BN_is_zero(current_exp)) {
        if (BN_is_odd(current_exp)) {
            if (!BN_mod_mul(temp, result, current_base, mod, ctx)) {
                BN_free(result);
                BN_free(current_base);
                BN_free(current_exp);
                BN_free(temp);
                throw std::runtime_error("BN_mod_mul failed in mod_pow");
            }
            BN_copy(result, temp);
        }

        if (!BN_mod_mul(temp, current_base, current_base, mod, ctx)) {
            BN_free(result);
            BN_free(current_base);
            BN_free(current_exp);
            BN_free(temp);
            throw std::runtime_error("BN_mod_mul failed while squaring in mod_pow");
        }
        BN_copy(current_base, temp);

        if (!BN_rshift1(current_exp, current_exp)) {
            BN_free(result);
            BN_free(current_base);
            BN_free(current_exp);
            BN_free(temp);
            throw std::runtime_error("BN_rshift1 failed in mod_pow");
        }
    }

    BN_free(current_base);
    BN_free(current_exp);
    BN_free(temp);
    return result;
}

inline KeyPair generate_keypair(BN_CTX *ctx) {
    KeyPair kp;
    kp.p = BN_new();
    kp.g = BN_new();
    kp.priv = BN_new();
    kp.pub = BN_new();

    if (!kp.p || !kp.g || !kp.priv || !kp.pub)
        throw std::runtime_error("BN_new failed");

    if (!BN_hex2bn(&kp.p, GROUP14_PRIME_HEX_CANONICAL))
        throw std::runtime_error("failed to load DH prime");
    if (!BN_dec2bn(&kp.g, GROUP14_GENERATOR_DEC))
        throw std::runtime_error("failed to load DH generator");

    BIGNUM *one = BN_new();
    BN_one(one);
    do {
        if (!BN_rand_range(kp.priv, kp.p)) {
            BN_free(one);
            throw std::runtime_error("BN_rand_range failed");
        }
    } while (BN_cmp(kp.priv, one) <= 0);
    BN_free(one);

    BIGNUM *public_value = mod_pow(kp.g, kp.priv, kp.p, ctx);
    if (!public_value)
        throw std::runtime_error("custom modular exponentiation failed while computing public value");

    BN_copy(kp.pub, public_value);
    BN_free(public_value);

    return kp;
}

inline BIGNUM *compute_shared_secret(const KeyPair &kp, const BIGNUM *peer_pub, BN_CTX *ctx) {
    BIGNUM *shared = mod_pow(peer_pub, kp.priv, kp.p, ctx);
    if (!shared) {
        throw std::runtime_error("custom modular exponentiation failed while computing shared secret");
    }
    return shared;
}

inline std::array<unsigned char, 32> derive_aes_key(const BIGNUM *shared_secret) {
    int len = BN_num_bytes(shared_secret);
    std::vector<unsigned char> raw(static_cast<size_t>(len));
    BN_bn2bin(shared_secret, raw.data());

    std::array<unsigned char, 32> key{};
    SHA256(raw.data(), raw.size(), key.data());
    OPENSSL_cleanse(raw.data(), raw.size());
    return key;
}

inline std::string fingerprint_hex(const std::array<unsigned char, 32> &key) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(key.data(), key.size(), digest);

    static const char *hexchars = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : digest) {
        out.push_back(hexchars[(b >> 4) & 0xF]);
        out.push_back(hexchars[b & 0xF]);
    }
    return out;
}

} // namespace dh
