#include <atomic>
#include <iostream>
#include <limits>
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
#include <openssl/x509.h>

#include "helpers.h"
#include "pki_utils.h"

using namespace std;

constexpr int SERVER_PORT = 5000;

mutex cout_mutex;
mutex send_mutex;
mutex e2e_mutex;
atomic<bool> quitting{false};

struct E2ESession {
    aesgcm::Key key{};
    bool established = false;
    dh::KeyPair pending_keypair;
    vector<string> pending_messages;
};

map<string, E2ESession> e2e_sessions;

static bool send_client_message(int sock_fd, const aesgcm::Key &key, const string &message) {
    lock_guard<mutex> lock(send_mutex);
    return aesgcm::send_encrypted(sock_fd, key, message);
}

static bool send_to_peer(int sock_fd, const aesgcm::Key &server_key,
                         const string &peer, const string &payload) {
    return send_client_message(sock_fd, server_key, "@" + peer + " " + payload);
}

static bool establish_e2e_session(int sock_fd, const aesgcm::Key &server_key,
                                  const string &peer) {
    lock_guard<mutex> lock(e2e_mutex);
    E2ESession &session = e2e_sessions[peer];
    if (session.established || session.pending_keypair.pub) return true;

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) return false;
    try {
        session.pending_keypair = dh::generate_keypair(ctx);
        string public_hex = dh::bn_to_hex(session.pending_keypair.pub);
        BN_CTX_free(ctx);
        return send_to_peer(sock_fd, server_key, peer, "__E2E_INIT__" + public_hex);
    } catch (const exception &e) {
        cerr << "E2E DH initialization error: " << e.what() << endl;
        dh::free_keypair(session.pending_keypair);
        BN_CTX_free(ctx);
        return false;
    }
}

static bool handle_e2e_control(int sock_fd, const aesgcm::Key &server_key,
                               const string &message) {
    const string prefixes[] = {"__E2E_INIT__", "__E2E_ACK__", "__E2E_MSG__"};
    string prefix;
    for (const string &candidate : prefixes) {
        if (message.rfind(candidate, 0) == 0) {
            prefix = candidate;
            break;
        }
    }
    if (prefix.empty()) return false;

    size_t separator = message.find('|', prefix.size());
    if (separator == string::npos || separator == prefix.size()) return true;
    string peer = message.substr(prefix.size(), separator - prefix.size());
    string data = message.substr(separator + 1);

    if (prefix == "__E2E_MSG__") {
        vector<unsigned char> blob;
        string plaintext;
        aesgcm::Key peer_key{};
        bool has_peer_key = false;
        {
            lock_guard<mutex> lock(e2e_mutex);
            auto session = e2e_sessions.find(peer);
            if (session != e2e_sessions.end() && session->second.established) {
                peer_key = session->second.key;
                has_peer_key = true;
            }
        }
        if (!pki::from_hex(data, blob) || !has_peer_key ||
            !aesgcm::decrypt(peer_key, blob, plaintext)) {
            lock_guard<mutex> output_lock(cout_mutex);
            cout << "\n[SECURITY] Rejected invalid end-to-end message.\n> ";
            cout.flush();
            return true;
        }
        lock_guard<mutex> output_lock(cout_mutex);
        cout << "\nYou received this from client " << peer << ": " << plaintext << "\n> ";
        cout.flush();
        return true;
    }

    BIGNUM *peer_public = nullptr;
    if (data.empty() || !dh::hex_to_bn(&peer_public, data)) return true;
    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) { BN_free(peer_public); return true; }

    bool send_ack = prefix == "__E2E_INIT__";
    string ack_public;
    vector<string> queued;
    {
        lock_guard<mutex> lock(e2e_mutex);
        E2ESession &session = e2e_sessions[peer];
        if (!session.pending_keypair.pub) {
            dh::free_keypair(session.pending_keypair);
            session.pending_keypair = dh::generate_keypair(ctx);
        }
        BIGNUM *shared = dh::compute_shared_secret(session.pending_keypair, peer_public, ctx);
        session.key = dh::derive_aes_key(shared);
        session.established = true;
        queued.swap(session.pending_messages);
        if (send_ack) ack_public = dh::bn_to_hex(session.pending_keypair.pub);
        BN_clear_free(shared);
        if (!send_ack) dh::free_keypair(session.pending_keypair);
    }
    BN_free(peer_public);
    BN_CTX_free(ctx);

    if (send_ack && !send_to_peer(sock_fd, server_key, peer, "__E2E_ACK__" + ack_public))
        return true;

    for (const string &pending : queued) {
        lock_guard<mutex> lock(e2e_mutex);
        vector<unsigned char> encrypted = aesgcm::encrypt(e2e_sessions[peer].key, pending);
        string payload = "__E2E_MSG__" + pki::to_hex(encrypted.data(), encrypted.size());
        if (!send_to_peer(sock_fd, server_key, peer, payload)) break;
    }
    return true;
}

static bool send_e2e_message(int sock_fd, const aesgcm::Key &server_key,
                             const string &peer, const string &message) {
    bool established = false;
    {
        lock_guard<mutex> lock(e2e_mutex);
        E2ESession &session = e2e_sessions[peer];
        established = session.established;
        if (!established) session.pending_messages.push_back(message);
        else {
            vector<unsigned char> encrypted = aesgcm::encrypt(session.key, message);
            return send_to_peer(sock_fd, server_key, peer,
                                "__E2E_MSG__" + pki::to_hex(encrypted.data(), encrypted.size()));
        }
    }
    return establish_e2e_session(sock_fd, server_key, peer);
}

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

        if (handle_e2e_control(sock_fd, key, message)) continue;

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

    int port = SERVER_PORT;
    cout << "Enter server port : ";
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
    string active_peer;
    cout << "\n";

    while (true) {
        cout << "> ";
        cout.flush();

        if (!getline(cin, message)) break;
        if (message.empty()) continue;

        message = trim_message(message);
        if (message.rfind("/chat ", 0) == 0) {
            active_peer = message.substr(6);
            if (!send_client_message(sock_fd, key, message)) {
                perror("Send failed");
                break;
            }
            continue;
        }

        string peer = active_peer;
        string chat_text = message;
        if (!message.empty() && message[0] == '@') {
            size_t space_pos = message.find(' ');
            if (space_pos != string::npos) {
                peer = message.substr(1, space_pos - 1);
                chat_text = message.substr(space_pos + 1);
                active_peer = peer;
            }
        }

        if (peer.empty() && !message.empty() && message[0] != '/' && message[0] != '#') {
            lock_guard<mutex> output_lock(cout_mutex);
            cout << "Error: chat partner not selected. Use /chat <username> first.\n";
            continue;
        }

        bool sent = false;
        if (!peer.empty() && chat_text.rfind("/", 0) != 0) {
            sent = send_e2e_message(sock_fd, key, peer, chat_text);
        } else {
            sent = send_client_message(sock_fd, key, message);
        }

        if (!sent) {
            perror("Send failed");
            break;
        }

        if (message == "/quit") break;
    }

    quitting.store(true);
    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);

    if (receiver.joinable()) receiver.join();

    lock_guard<mutex> lock(e2e_mutex);
    for (auto &entry : e2e_sessions) dh::free_keypair(entry.second.pending_keypair);

    cout << "Client exited.\n";
    return 0;
}

