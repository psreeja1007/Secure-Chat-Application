#include <atomic>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/x509.h>

#include "helpers.h"
#include "pki_utils.h"

using namespace std;

constexpr int DEFAULT_PORT = 5000;
constexpr int SERVER_PORT = 5000;



mutex cout_mutex;
atomic<bool> quitting{false};

static bool perform_dh_client(int sock_fd, aesgcm::Key &key_out) {
    constexpr const char *CA_CERT = "certs/ca.crt";
    constexpr const char *EXPECTED_SERVER_NAME = "Chat Server";

    cout << "[PKI] Waiting for server certificate...\n";
    string cert_pem;
    if (!pki::recv_blob(sock_fd, cert_pem)) {
        cerr << "[PKI] Failed to receive certificate.\n";
        return false;
    }

    BIO *bio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
    if (!bio) return false;
    X509 *server_cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!server_cert) {
        cerr << "[PKI] Invalid certificate received.\n";
        return false;
    }

    cout << "[PKI] Validating certificate...\n";
    if (!pki::verify_certificate(server_cert, CA_CERT, EXPECTED_SERVER_NAME)) {
        cerr << "[SECURITY] Server certificate rejected. Connection aborted.\n";
        X509_free(server_cert);
        return false;
    }
    cout << "[PKI] Certificate is valid.\n";
    cout << "[PKI] Trusted CA: YES\n";
    cout << "[PKI] Validity period: OK\n";
    cout << "[PKI] Server identity: OK\n";

    string challenge;
    if (!pki::generate_challenge(challenge)) {
        X509_free(server_cert);
        return false;
    }
    if (!send_plain(sock_fd, "AUTH_CHALLENGE " + challenge + "\n")) {
        X509_free(server_cert);
        return false;
    }

    string dh_init;
    if (!recv_plain_line(sock_fd, dh_init) || dh_init.rfind("DH_INIT ", 0) != 0) {
        cerr << "[PKI] Expected DH_INIT.\n";
        X509_free(server_cert);
        return false;
    }
    string server_public_key_hex = dh_init.substr(8);

    string sig_line;
    if (!recv_plain_line(sock_fd, sig_line) || sig_line.rfind("DH_SIGNATURE ", 0) != 0) {
        cerr << "[PKI] Expected DH signature.\n";
        X509_free(server_cert);
        return false;
    }
    vector<unsigned char> signature;
    if (!pki::from_hex(sig_line.substr(13), signature)) {
        cerr << "[PKI] Invalid signature format.\n";
        X509_free(server_cert);
        return false;
    }

    string signed_data = "CHAT-DH-PROOF|" + challenge + "|" + server_public_key_hex;
    cout << "[PKI] Verifying server private-key proof...\n";
    if (!pki::verify_signature(server_cert, signed_data, signature)) {
        cerr << "[SECURITY] Server proof-of-possession FAILED.\n";
        cerr << "[SECURITY] Connection aborted.\n";
        X509_free(server_cert);
        return false;
    }
    cout << "[PKI] Server proof-of-possession: VALID\n";
    X509_free(server_cert);

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;
    try {
        dh::KeyPair key_pair = dh::generate_keypair(ctx);
        BIGNUM *server_public_key = nullptr;
        if (!dh::hex_to_bn(&server_public_key, server_public_key_hex)) {
            dh::free_keypair(key_pair); BN_CTX_free(ctx); return false;
        }

        string client_reply = "DH_RESP " + dh::bn_to_hex(key_pair.pub) + "\n";
        if (!send_plain(sock_fd, client_reply)) {
            BN_free(server_public_key); dh::free_keypair(key_pair); BN_CTX_free(ctx); return false;
        }

        string server_ack;
        if (!recv_plain_line(sock_fd, server_ack) || server_ack != "DH_OK") {
            cerr << "Unexpected DH completion response.\n";
            BN_free(server_public_key); dh::free_keypair(key_pair); BN_CTX_free(ctx); return false;
        }

        BIGNUM *shared_secret = dh::compute_shared_secret(key_pair, server_public_key, ctx);
        key_out = dh::derive_aes_key(shared_secret);
        cout << "[DH] Shared key established with server | fingerprint: "
             << dh::fingerprint_hex(key_out) << endl;

        BN_free(server_public_key);
        BN_clear_free(shared_secret);
        dh::free_keypair(key_pair);
        BN_CTX_free(ctx);
        return true;
    } catch (const exception &e) {
        cerr << "DH handshake error: " << e.what() << endl;
        BN_CTX_free(ctx);
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

    int port = DEFAULT_PORT;
    cout << "Enter server port [5000]: ";
    string port_input;
    getline(cin, port_input);
    if (!port_input.empty()) port = stoi(port_input);

    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

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

