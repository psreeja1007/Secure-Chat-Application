#include <bits/stdc++.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <mutex>

#include "helpers.h"

using namespace std;

#define SERVER_PORT 5000
mutex cout_mutex;

void receive_messages(int sock_fd)
{
    char buffer[1024];
    while (true)
    {
        memset(buffer, 0, sizeof(buffer));

        int bytes_received = recv(
            sock_fd,
            buffer,
            sizeof(buffer) - 1,
            0
        );

        // Server disconnected / receive error
        if (bytes_received <= 0)
        {
            lock_guard<mutex> lock(cout_mutex);

            if (bytes_received == 0)
                cout << "\nServer disconnected.\n";
            else
                perror("Receive failed");

            cout << "Exiting client...\n";
            exit(0);
        }

        buffer[bytes_received] = '\0';

        {
            lock_guard<mutex> lock(cout_mutex);

            cout << "\n" << buffer;
            cout << "> ";
            cout.flush();
        }
    }
}

int main()
{
    string server_ip;

    cout << "Enter server IP: ";
    cin >> server_ip;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    int port = DEFAULT_PORT;
    cout << "Enter server port : ";
    string port_input;
    getline(cin, port_input);
    if (!port_input.empty()) port = stoi(port_input);

    // 1. Create TCP socket
    int sock_fd = socket(
        AF_INET,
        SOCK_STREAM,
        0
    );

    if (sock_fd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    // 2. Set up server address
    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(
            AF_INET,
            server_ip.c_str(),
            &server_addr.sin_addr) <= 0)
    {
        cerr << "Invalid server IP address\n";
        close(sock_fd);
        return 1;
    }

    // 3. Connect to server
    if (connect(
            sock_fd,
            (struct sockaddr*)&server_addr,
            sizeof(server_addr)) < 0)
    {
        perror("Connection failed");
        close(sock_fd);
        return 1;
    }

    cout << "\nConnected to server "
         << server_ip
         << ":"
         << port
         << endl;

    // 4. Start receiver thread
    thread receiver(
        receive_messages,
        sock_fd
    );

    // 5. Command-line interface
    string message;
    cout << "\n";

    while (true)
    {
        cout << "> ";
        cout.flush();

        if (!getline(cin, message))
        {
            break;
        }

        if (message.empty())
        {
            continue;
        }

        if (!send_plain(sock_fd, message))
        {
            perror("Send failed");
            break;
        }

        // /quit
        if (message == "/quit")
        {
            break;
        }
    }

    shutdown(sock_fd, SHUT_RDWR);
    close(sock_fd);

    // Wait for receiver thread
    if (receiver.joinable())
    {
        receiver.join();
    }

    cout << "Client exited.\n";
    return 0;
}