#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/evp.h>

#include "helpers.h"
#include "pki_utils.h"

using namespace std;

constexpr int SERVER_PORT = 5000;

mutex cout_mutex;
mutex users_mutex;
map<string, int> client_sockets;
map<string, string> chat_partner;
map<string, aesgcm::Key> client_keys;

// Server-side DH exchange: generate keypair, send public value, receive
// client's public value, compute shared secret, and derive the AES key.
static bool perform_dh_server(int client_fd, const string &client_ip, aesgcm::Key &key_out) {
    constexpr const char *SERVER_CERT = "certs/server.crt";
    constexpr const char *SERVER_KEY = "private/server.key";

    string cert_pem;
    if (!pki::read_file(SERVER_CERT, cert_pem)) {
        cerr << "[PKI] Could not read server certificate.\n";
        return false;
    }
    cout << "[PKI] Sending server certificate to " << client_ip << "\n";
    if (!pki::send_blob(client_fd, cert_pem)) return false;

    string challenge_line;
    if (!recv_plain_line(client_fd, challenge_line) || challenge_line.rfind("AUTH_CHALLENGE ", 0) != 0) {
        cerr << "[PKI] Invalid authentication challenge.\n";
        return false;
    }
    string challenge = challenge_line.substr(15);
    if (challenge.empty()) return false;

    EVP_PKEY *private_key = pki::load_private_key(SERVER_KEY);
    if (!private_key) {
        cerr << "[PKI] Could not load server private key.\n";
        return false;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { EVP_PKEY_free(private_key); return false; }
    dh::KeyPair key_pair;
    try {
        key_pair = dh::generate_keypair(ctx);
        string server_public = dh::bn_to_hex(key_pair.pub);
        string signed_data = "CHAT-DH-PROOF|" + challenge + "|" + server_public;
        vector<unsigned char> signature;
        if (!pki::sign_data(private_key, signed_data, signature)) {
            dh::free_keypair(key_pair); BN_CTX_free(ctx); EVP_PKEY_free(private_key); return false;
        }
        string signature_hex = pki::to_hex(signature.data(), signature.size());

        if (!send_plain(client_fd, "DH_INIT " + server_public + "\n") ||
            !send_plain(client_fd, "DH_SIGNATURE " + signature_hex + "\n")) {
            dh::free_keypair(key_pair); BN_CTX_free(ctx); EVP_PKEY_free(private_key); return false;
        }

        string client_reply;
        if (!recv_plain_line(client_fd, client_reply) || client_reply.rfind("DH_RESP ", 0) != 0) {
            dh::free_keypair(key_pair); BN_CTX_free(ctx); EVP_PKEY_free(private_key); return false;
        }
        BIGNUM *peer_public = nullptr;
        if (!dh::hex_to_bn(&peer_public, client_reply.substr(8))) {
            dh::free_keypair(key_pair); BN_CTX_free(ctx); EVP_PKEY_free(private_key); return false;
        }

        BIGNUM *shared = dh::compute_shared_secret(key_pair, peer_public, ctx);
        key_out = dh::derive_aes_key(shared);
        cout << "[DH] Shared key established with " << client_ip
             << " | fingerprint: " << dh::fingerprint_hex(key_out) << endl;

        bool sent = send_plain(client_fd, "DH_OK\n");
        BN_free(peer_public); BN_clear_free(shared); dh::free_keypair(key_pair);
        BN_CTX_free(ctx); EVP_PKEY_free(private_key);
        return sent;
    } catch (const exception &e) {
        cerr << "DH handshake error with " << client_ip << ": " << e.what() << endl;
        dh::free_keypair(key_pair); BN_CTX_free(ctx); EVP_PKEY_free(private_key);
        return false;
    }
}

// One connection = one authenticated user session. The actual chat logic
// is simple; the helper header handles the shared crypto/socket utilities.
static void handle_client(int client_fd, const string &client_ip) {
    aesgcm::Key key{};
    if (!perform_dh_server(client_fd, client_ip, key)) {
        close(client_fd);
        return;
    }

    if (!aesgcm::send_encrypted(client_fd, key, "Hello from server. Please register.\n")) {
        close(client_fd);
        return;
    }

    string username;
    bool registered = false;

    while (!registered) {
        string message;
        auto status = aesgcm::recv_encrypted(client_fd, key, message);

        if (status == aesgcm::RecvStatus::DISCONNECTED) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "Client disconnected before registration: " << client_ip << endl;
            close(client_fd);
            return;
        }
        if (status == aesgcm::RecvStatus::AUTH_FAILED) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[SECURITY] Rejected tampered/undecryptable message from "
                 << client_ip << " during registration." << endl;
            close(client_fd);
            return;
        }
        if (status == aesgcm::RecvStatus::ERROR) {
            close(client_fd);
            return;
        }

        message = trim_message(message);
        const string prefix = "#register ";

        if (message.rfind(prefix, 0) != 0) {
            aesgcm::send_encrypted(client_fd, key, "Invalid format. Please use: #register <username>\n");
            continue;
        }

        username = message.substr(prefix.length());
        if (username.empty()) {
            aesgcm::send_encrypted(client_fd, key, "Username cannot be empty. Please use: #register <username>\n");
            continue;
        }

        {
            lock_guard<mutex> lock(users_mutex);
            if (client_sockets.find(username) != client_sockets.end()) {
                aesgcm::send_encrypted(client_fd, key, "Username already taken. Select another one.\n");
                continue;
            }
            client_sockets[username] = client_fd;
            client_keys[username] = key;
            chat_partner[username] = "";
            registered = true;
        }

        aesgcm::send_encrypted(client_fd, key, "Successfully registered as " + username + "\n");

        lock_guard<mutex> lock(cout_mutex);
        cout << "User registered: " << username << " -> " << client_ip << endl;
    }

    while (true) {
        string message;
        auto status = aesgcm::recv_encrypted(client_fd, key, message);

        if (status == aesgcm::RecvStatus::DISCONNECTED) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "Client disconnected: " << username << " (" << client_ip << ")" << endl;
            break;
        }
        if (status == aesgcm::RecvStatus::AUTH_FAILED) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[SECURITY] Rejected tampered/undecryptable message from "
                 << username << " (" << client_ip << "). Closing connection." << endl;
            break;
        }
        if (status == aesgcm::RecvStatus::ERROR) break;

        message = trim_message(message);

        if (!message.empty() && message[0] == '@') {
            size_t space_pos = message.find(' ');
            if (space_pos != string::npos) {
                string target_username = message.substr(1, space_pos - 1);
                string actual_message = message.substr(space_pos + 1);

                int target_fd = -1;
                aesgcm::Key target_key{};
                {
                    lock_guard<mutex> lock(users_mutex);
                    auto it = client_sockets.find(target_username);
                    if (it != client_sockets.end()) {
                        target_fd = it->second;
                        target_key = client_keys[target_username];
                    }
                }

                if (target_fd == -1) {
                    aesgcm::send_encrypted(client_fd, key, "User " + target_username + " is not online.\n");
                    continue;
                }

                aesgcm::send_encrypted(target_fd, target_key,
                    "You received this from client " + username + ": " + actual_message + "\n");

                {
                    lock_guard<mutex> lock(cout_mutex);
                    cout << username << " -> " << target_username << ": " << actual_message << endl;
                }

                {
                    lock_guard<mutex> lock(users_mutex);
                    chat_partner[username] = target_username;
                }
                continue;
            }
        }

        if (message.rfind("/chat ", 0) == 0) {
            string target_username = message.substr(6);
            bool user_exists = false;
            {
                lock_guard<mutex> lock(users_mutex);
                if (client_sockets.find(target_username) != client_sockets.end()) {
                    user_exists = true;
                    chat_partner[username] = target_username;
                }
            }
            if (!user_exists)
                aesgcm::send_encrypted(client_fd, key, "User " + target_username + " is not online.\n");
            continue;
        }

        if (message == "/who") {
            string reply = "Online users:\n";
            {
                lock_guard<mutex> lock(users_mutex);
                for (const auto &user : client_sockets)
                    reply += "- " + user.first + "\n";
            }
            aesgcm::send_encrypted(client_fd, key, reply);
            continue;
        }

        if (message == "/quit") {
            aesgcm::send_encrypted(client_fd, key, "Goodbye!\n");
            break;
        }

        string target_username;
        {
            lock_guard<mutex> lock(users_mutex);
            target_username = chat_partner[username];
        }

        if (target_username.empty()) {
            aesgcm::send_encrypted(client_fd, key, "No chatting partner selected. Use /chat <username> first.\n");
            continue;
        }

        int target_fd = -1;
        aesgcm::Key target_key{};
        {
            lock_guard<mutex> lock(users_mutex);
            auto it = client_sockets.find(target_username);
            if (it != client_sockets.end()) {
                target_fd = it->second;
                target_key = client_keys[target_username];
            }
        }

        if (target_fd == -1) {
            aesgcm::send_encrypted(client_fd, key, "User " + target_username + " is no longer online.\n");
            continue;
        }

        aesgcm::send_encrypted(target_fd, target_key,
            "You received this from client " + username + ": " + message + "\n");

        lock_guard<mutex> lock(cout_mutex);
        cout << username << " -> " << target_username << ": " << message << endl;
    }

    {
        lock_guard<mutex> lock(users_mutex);
        client_sockets.erase(username);
        client_keys.erase(username);
        chat_partner.erase(username);
        for (auto &entry : chat_partner) {
            if (entry.second == username) entry.second = "";
        }
    }

    close(client_fd);
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_fd, reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    cout << "Server bound to port " << SERVER_PORT << endl;

    if (listen(server_fd, 4) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    cout << "Server listening..." << endl;

    while (true) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, reinterpret_cast<struct sockaddr *>(&client_addr), &client_len);
        if (client_fd < 0) {
            perror("Accept failed");
            continue;
        }

        string client_ip = inet_ntoa(client_addr.sin_addr);
        cout << "New client connected: " << client_ip << endl;
        thread(handle_client, client_fd, client_ip).detach();
    }

    close(server_fd);
    return 0;
}
