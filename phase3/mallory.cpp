#include <atomic>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/bn.h>

#include "helpers.h"
#include "pki_utils.h"

using namespace std;

// ============================================================
// CONFIGURATION
// ============================================================

// Victim connects to Mallory on this port.
constexpr int MALLORY_PORT = 5001;

// Mallory connects to the REAL server on this port.
constexpr int SERVER_PORT = 5000;

// CHANGE THIS to the REAL SERVER VM IP.
constexpr const char *SERVER_IP = "192.168.0.104";

mutex cout_mutex;
atomic<bool> stopping{false};


// ============================================================
// SOCKET CLEANUP
// ============================================================

static void close_socket(int &fd)
{
    if (fd >= 0) {
        shutdown(fd, SHUT_RDWR);
        close(fd);
        fd = -1;
    }
}


// ============================================================
// FORWARD THE SERVER CERTIFICATE TO CLIENT
// ============================================================
//
// Real server:
//
//     sends server.crt
//
// Mallory:
//
//     receives it
//          |
//          v
//     sends SAME certificate to client
//
// This is important because Mallory does NOT need to modify
// the certificate for the MITM attempt.
//
// The client will validate the certificate itself.
// ============================================================

static bool relay_server_certificate(
    int server_fd,
    int client_fd)
{
    cout << "\n[MALLORY] Waiting for real server certificate...\n";

    string certificate;

    if (!pki::recv_blob(server_fd, certificate)) {
        cerr << "[MALLORY] Failed to receive certificate from real server.\n";
        return false;
    }

    cout << "[MALLORY] Received server certificate from real server.\n";

    cout << "[MALLORY] Relaying certificate to victim client...\n";

    if (!pki::send_blob(client_fd, certificate)) {
        cerr << "[MALLORY] Failed to send certificate to victim.\n";
        return false;
    }

    cout << "[MALLORY] Certificate successfully relayed.\n";

    return true;
}


// ============================================================
// RELAY CLIENT CHALLENGE TO REAL SERVER
// ============================================================
//
// Client:
//
//     AUTH_CHALLENGE <random>
//
// Mallory:
//
//     receives it
//     forwards EXACT SAME challenge to server
//
// This keeps the conversation identical to the legitimate
// protocol.
// ============================================================

static bool relay_client_challenge(
    int client_fd,
    int server_fd,
    string &challenge_line)
{
    cout << "\n[MALLORY] Waiting for client authentication challenge...\n";

    if (!recv_plain_line(client_fd, challenge_line)) {
        cerr << "[MALLORY] Client disconnected while waiting for challenge.\n";
        return false;
    }

    cout << "[MALLORY] Client sent:\n";
    cout << "          " << challenge_line << "\n";

    if (challenge_line.rfind("AUTH_CHALLENGE ", 0) != 0) {
        cerr << "[MALLORY] Unexpected client message.\n";
        return false;
    }

    cout << "[MALLORY] Relaying challenge to real server...\n";

    if (!send_plain(server_fd, challenge_line + "\n")) {
        cerr << "[MALLORY] Failed to relay challenge to server.\n";
        return false;
    }

    cout << "[MALLORY] Challenge forwarded.\n";

    return true;
}


// ============================================================
// ATTEMPT MITM DH WITH CLIENT
// ============================================================
//
// The REAL server sends:
//
//     DH_INIT <server_public>
//     DH_SIGNATURE <signature>
//
// Mallory wants to replace:
//
//     real_server_public
//
// with:
//
//     mallory_public
//
// so that:
//
//     Client <-> Mallory
//
// would have a different key.
//
// BUT:
//
// The real server's signature is over:
//
//     CHAT-DH-PROOF |
//     challenge |
//     real_server_public
//
// Therefore Mallory cannot simply replace the public key.
//
// The client will detect:
//
//     signature != expected signature
//
// and abort.
//
// This is the exact Phase-3 defense we want to demonstrate.
// ============================================================

static bool attempt_client_side_mitm(
    int client_fd,
    int server_fd,
    const string &challenge_line)
{
    cout << "\n";
    cout << "============================================\n";
    cout << "[MALLORY] ATTEMPTING CLIENT-SIDE MITM\n";
    cout << "============================================\n";

    // --------------------------------------------------------
    // Receive the legitimate server DH_INIT.
    // --------------------------------------------------------

    string real_dh_init;

    if (!recv_plain_line(server_fd, real_dh_init)) {
        cerr << "[MALLORY] Real server disconnected.\n";
        return false;
    }

    if (real_dh_init.rfind("DH_INIT ", 0) != 0) {
        cerr << "[MALLORY] Expected DH_INIT from real server.\n";
        return false;
    }

    string real_server_public_hex = real_dh_init.substr(8);

    cout << "[MALLORY] Real server DH public key received.\n";
    cout << "[MALLORY] Real server public key length: "
         << real_server_public_hex.size()
         << " hex characters.\n";


    // --------------------------------------------------------
    // Receive legitimate server signature.
    // --------------------------------------------------------

    string signature_line;

    if (!recv_plain_line(server_fd, signature_line)) {
        cerr << "[MALLORY] Real server disconnected before signature.\n";
        return false;
    }

    if (signature_line.rfind("DH_SIGNATURE ", 0) != 0) {
        cerr << "[MALLORY] Expected DH_SIGNATURE from real server.\n";
        return false;
    }

    string signature_hex = signature_line.substr(13);

    cout << "[MALLORY] Real server DH signature received.\n";


    // --------------------------------------------------------
    // Generate Mallory's own DH key.
    // --------------------------------------------------------
    //
    // Mallory wants:
    //
    //     Client <-> Mallory
    //
    // instead of:
    //
    //     Client <-> Server
    //
    // So Mallory generates a different DH public value.
    // --------------------------------------------------------

    BN_CTX *ctx = BN_CTX_new();

    if (!ctx) {
        cerr << "[MALLORY] BN_CTX_new failed.\n";
        return false;
    }

    dh::KeyPair mallory_keypair;

    try {

        mallory_keypair = dh::generate_keypair(ctx);

        string mallory_public_hex =
            dh::bn_to_hex(mallory_keypair.pub);

        cout << "[MALLORY] Generated Mallory DH key pair.\n";
        cout << "[MALLORY] Mallory public key is DIFFERENT from server key.\n";


        // ----------------------------------------------------
        // THE ATTACK
        // ----------------------------------------------------
        //
        // Send Mallory's DH public value to the client.
        //
        // But forward the REAL SERVER'S signature.
        //
        // This should FAIL.
        // ----------------------------------------------------

        string fake_dh_init =
            "DH_INIT " + mallory_public_hex + "\n";

        cout << "\n[MALLORY] Replacing server DH public key!\n";
        cout << "[MALLORY] Sending Mallory's DH_INIT to victim...\n";

        if (!send_plain(client_fd, fake_dh_init)) {

            cerr << "[MALLORY] Failed to send fake DH_INIT.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }


        // ----------------------------------------------------
        // Forward the REAL SERVER signature unchanged.
        // ----------------------------------------------------
        //
        // The signature was generated over:
        //
        //     challenge + REAL server public key
        //
        // but the client received:
        //
        //     challenge + MALLORY public key
        //
        // Therefore verification must fail.
        // ----------------------------------------------------

        cout << "[MALLORY] Forwarding REAL server signature...\n";

        if (!send_plain(client_fd, signature_line + "\n")) {

            cerr << "[MALLORY] Failed to forward signature.\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return false;
        }

        cout << "\n";
        cout << "============================================\n";
        cout << "[MALLORY] ATTACK SENT TO CLIENT\n";
        cout << "============================================\n";
        cout << "Real server DH public key : REPLACED\n";
        cout << "Real server signature     : FORWARDED\n";
        cout << "Mallory private key       : NOT AVAILABLE\n";
        cout << "============================================\n";


        // ----------------------------------------------------
        // Wait for client's response.
        //
        // A secure client should close the connection.
        // ----------------------------------------------------

        string client_response;

        if (!recv_plain_line(client_fd, client_response)) {

            cout << "\n";
            cout << "============================================\n";
            cout << "[SECURITY] CLIENT REJECTED THE MITM\n";
            cout << "============================================\n";
            cout << "[MALLORY] Client closed the connection.\n";
            cout << "[MALLORY] Proof-of-possession verification blocked\n";
            cout << "          the substituted DH public key.\n";
            cout << "============================================\n";

            dh::free_keypair(mallory_keypair);
            BN_CTX_free(ctx);

            return true;
        }

        cout << "[MALLORY] Unexpected client response:\n";
        cout << "          " << client_response << "\n";

        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return false;

    }
    catch (const exception &e) {

        cerr << "[MALLORY] MITM error: "
             << e.what() << "\n";

        dh::free_keypair(mallory_keypair);
        BN_CTX_free(ctx);

        return false;
    }
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    cout << "============================================\n";
    cout << "          MALLORY PHASE 3 MITM\n";
    cout << "============================================\n";
    cout << "Mallory listen port : " << MALLORY_PORT << "\n";
    cout << "Real server IP      : " << SERVER_IP << "\n";
    cout << "Real server port    : " << SERVER_PORT << "\n";
    cout << "============================================\n\n";


    // ========================================================
    // 1. CREATE MALLORY LISTENING SOCKET
    // ========================================================

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd < 0) {
        perror("[MALLORY] socket");
        return 1;
    }

    int opt = 1;

    if (setsockopt(
            listen_fd,
            SOL_SOCKET,
            SO_REUSEADDR,
            &opt,
            sizeof(opt)) < 0)
    {
        perror("[MALLORY] setsockopt");

        close_socket(listen_fd);

        return 1;
    }


    // ========================================================
    // 2. BIND MALLORY PORT
    // ========================================================

    sockaddr_in mallory_addr{};

    mallory_addr.sin_family = AF_INET;
    mallory_addr.sin_port = htons(MALLORY_PORT);
    mallory_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
            listen_fd,
            reinterpret_cast<sockaddr *>(&mallory_addr),
            sizeof(mallory_addr)) < 0)
    {
        perror("[MALLORY] bind");

        close_socket(listen_fd);

        return 1;
    }


    // ========================================================
    // 3. LISTEN
    // ========================================================

    if (listen(listen_fd, 1) < 0) {

        perror("[MALLORY] listen");

        close_socket(listen_fd);

        return 1;
    }

    cout << "[MALLORY] Listening for victim client on port "
         << MALLORY_PORT << "...\n";


    // ========================================================
    // 4. ACCEPT VICTIM CLIENT
    // ========================================================

    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);

    int client_fd = accept(
        listen_fd,
        reinterpret_cast<sockaddr *>(&client_addr),
        &client_len);

    if (client_fd < 0) {

        perror("[MALLORY] accept");

        close_socket(listen_fd);

        return 1;
    }

    string client_ip = inet_ntoa(client_addr.sin_addr);

    cout << "[MALLORY] Victim connected from "
         << client_ip << "\n";


    // ========================================================
    // 5. CONNECT TO REAL SERVER
    // ========================================================

    cout << "\n[MALLORY] Connecting to real server "
         << SERVER_IP << ":"
         << SERVER_PORT << "...\n";

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (server_fd < 0) {

        perror("[MALLORY] server socket");

        close_socket(client_fd);
        close_socket(listen_fd);

        return 1;
    }

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(
            AF_INET,
            SERVER_IP,
            &server_addr.sin_addr) <= 0)
    {
        cerr << "[MALLORY] Invalid server IP: "
             << SERVER_IP << "\n";

        close_socket(server_fd);
        close_socket(client_fd);
        close_socket(listen_fd);

        return 1;
    }

    if (connect(
            server_fd,
            reinterpret_cast<sockaddr *>(&server_addr),
            sizeof(server_addr)) < 0)
    {
        perror("[MALLORY] connect to real server");

        close_socket(server_fd);
        close_socket(client_fd);
        close_socket(listen_fd);

        return 1;
    }

    cout << "[MALLORY] Connected to real server.\n";


    // ========================================================
    // 6. RELAY CERTIFICATE
    // ========================================================

    if (!relay_server_certificate(
            server_fd,
            client_fd))
    {
        cerr << "[MALLORY] Certificate relay failed.\n";

        close_socket(server_fd);
        close_socket(client_fd);
        close_socket(listen_fd);

        return 1;
    }


    // ========================================================
    // 7. RELAY CLIENT CHALLENGE
    // ========================================================

    string challenge_line;

    if (!relay_client_challenge(
            client_fd,
            server_fd,
            challenge_line))
    {
        cerr << "[MALLORY] Challenge relay failed.\n";

        close_socket(server_fd);
        close_socket(client_fd);
        close_socket(listen_fd);

        return 1;
    }


    // ========================================================
    // 8. ATTEMPT TO SUBSTITUTE DH KEY
    // ========================================================

    bool result = attempt_client_side_mitm(
        client_fd,
        server_fd,
        challenge_line);


    // ========================================================
    // 9. CLEANUP
    // ========================================================

    if (result) {

        cout << "\n";
        cout << "============================================\n";
        cout << "       PHASE 3 MITM DEFENSE VERIFIED\n";
        cout << "============================================\n";
        cout << "Mallory attempted to replace the server's\n";
        cout << "ephemeral DH public key.\n\n";
        cout << "The real server signature was forwarded,\n";
        cout << "but it did not authenticate Mallory's\n";
        cout << "replacement DH public key.\n\n";
        cout << "CLIENT REJECTED THE CONNECTION.\n";
        cout << "============================================\n";

    } else {

        cout << "\n[MALLORY] MITM test ended.\n";
    }

    close_socket(server_fd);
    close_socket(client_fd);
    close_socket(listen_fd);

    return 0;
}