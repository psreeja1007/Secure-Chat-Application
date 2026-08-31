#include <atomic>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "helpers.h"

using namespace std;

constexpr int SERVER_PORT = 5000;

mutex cout_mutex;
atomic<bool> quitting{false};

static bool perform_dh_client(int sock_fd, aesgcm::Key &key_out) {
    string server_handshake_line;
    if (!recv_plain_line(sock_fd, server_handshake_line)) {
        cout << "Server disconnected during DH handshake." << endl;
        return false;
    }

    if (server_handshake_line.rfind("DH_INIT ", 0) != 0) {
        cout << "Unexpected DH init message: " << server_handshake_line << endl;
        return false;
    }

    string server_public_key_hex = server_handshake_line.substr(8);
    if (server_public_key_hex.empty()) {
        cout << "Malformed DH init message." << endl;
        return false;
    }

    BN_CTX *bignum_context = BN_CTX_new();
    if (!bignum_context) {
        perror("BN_CTX_new failed");
        return false;
    }

    try {
        dh::KeyPair key_pair = dh::generate_keypair(bignum_context);

        BIGNUM *server_public_key = nullptr;
        if (!dh::hex_to_bn(&server_public_key, server_public_key_hex)) {
            cout << "Failed to parse server DH public value." << endl;
            dh::free_keypair(key_pair);
            BN_CTX_free(bignum_context);
            return false;
        }

        string client_reply = "DH_RESP " + dh::bn_to_hex(key_pair.pub) + "\n";
        if (!send_plain(sock_fd, client_reply)) {
            perror("DH response send failed");
            BN_free(server_public_key);
            dh::free_keypair(key_pair);
            BN_CTX_free(bignum_context);
            return false;
        }

        string server_ack;
        if (!recv_plain_line(sock_fd, server_ack)) {
            cout << "Server disconnected before DH completion." << endl;
            BN_free(server_public_key);
            dh::free_keypair(key_pair);
            BN_CTX_free(bignum_context);
            return false;
        }
        if (server_ack != "DH_OK") {
            cout << "Unexpected DH completion response: " << server_ack << endl;
            BN_free(server_public_key);
            dh::free_keypair(key_pair);
            BN_CTX_free(bignum_context);
            return false;
        }

        BIGNUM *shared_secret = dh::compute_shared_secret(key_pair, server_public_key, bignum_context);
        key_out = dh::derive_aes_key(shared_secret);

        {
            lock_guard<mutex> lock(cout_mutex);
            cout << "[DH] Shared key established with server | fingerprint: "
                 << dh::fingerprint_hex(key_out) << endl;
        }

        BN_free(server_public_key);
        BN_clear_free(shared_secret);
        dh::free_keypair(key_pair);
        BN_CTX_free(bignum_context);
        return true;
    } catch (const std::exception &e) {
        cerr << "DH handshake error: " << e.what() << endl;
        BN_CTX_free(bignum_context);
        return false;
    }
}

static void receive_messages(int sock_fd, aesgcm::Key key) {
    while (true) {
        std::string message;
        auto status = aesgcm::recv_encrypted(sock_fd, key, message);

        if (status == aesgcm::RecvStatus::DISCONNECTED) {
            if (quitting.load()) return;
            lock_guard<mutex> lock(cout_mutex);
            cout << "\nServer disconnected.\nExiting client...\n";
            exit(0);
        }
        if (status == aesgcm::RecvStatus::AUTH_FAILED) {
            lock_guard<mutex> lock(cout_mutex);
            cout << "\n[SECURITY] Received tampered ciphertext and rejected it.\n> ";
            cout.flush();
            continue;
        }
        if (status == aesgcm::RecvStatus::ERROR) {
            if (quitting.load()) return;
            lock_guard<mutex> lock(cout_mutex);
            cout << "\nConnection error. Exiting client...\n";
            exit(1);
        }

        lock_guard<mutex> lock(cout_mutex);
        cout << "\n" << message;
        cout << "> ";
        cout.flush();
    }
}

int main() {
    string server_ip;
    cout << "Enter server IP: ";
    cin >> server_ip;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
        cerr << "Invalid server IP address\n";
        close(sock_fd);
        return 1;
    }

    if (connect(sock_fd, reinterpret_cast<struct sockaddr *>(&server_addr), sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(sock_fd);
        return 1;
    }

    aesgcm::Key key{};
    if (!perform_dh_client(sock_fd, key)) {
        close(sock_fd);
        return 1;
    }

    cout << "\nConnected to server " << server_ip << ":" << SERVER_PORT << endl;
    cout << "All further traffic on this link is AES-256-GCM encrypted.\n";

    thread receiver(receive_messages, sock_fd, key);
    string message;
    cout << "\n";

    while (true) {
        cout << "> ";
        cout.flush();

        if (!getline(cin, message)) break;
        if (message.empty()) continue;

        if (!aesgcm::send_encrypted(sock_fd, key, message)) {
            perror("Send failed");
            break;
        }

        if (message == "/quit") break;
    }

    quitting.store(true);
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);

    if (receiver.joinable()) receiver.join();

    cout << "Client exited.\n";
    return 0;
}

