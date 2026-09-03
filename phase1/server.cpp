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
mutex users_mutex;

map<string, string> registered_users;
map<string, int> client_sockets;
map<string, string> chat_partner;

bool send_message(int client_fd, const string &message){
    return send_plain(client_fd, message);
}

void handle_client(int client_fd, string client_ip){
    char buffer[1024];

    string welcome = "Hello from server. Please register.\n";

    if (!send_message(client_fd, welcome)){
        perror("Send failed");
        close(client_fd);
        return;
    }

    string username = "";
    bool registered = false;

    // Wait for registration
    while (!registered){
        memset(buffer, 0, sizeof(buffer));

        int bytes_received = recv(client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received < 0){
            perror("Receive failed");
            close(client_fd);
            return;
        }

        if (bytes_received == 0){
            lock_guard<mutex> lock(cout_mutex);
            cout << "Client disconnected before registration: " << client_ip << endl;
            close(client_fd);
            return;
        }

        buffer[bytes_received] = '\0';
        string message(buffer);
        message = trim_message(message);

        const string prefix = "#register ";

        if (message.rfind(prefix, 0) != 0)
        {
            string reply =
                "Invalid format. Please use: "
                "#register <username>\n";

            send_message(client_fd, reply);
            continue;
        }

        username = message.substr(prefix.length());

        if (username.empty())
        {
            string reply =
                "Username cannot be empty. "
                "Please use: #register <username>\n";

            send_message(client_fd, reply);

            continue;
        }

        // Check if username is already taken
        {
            lock_guard<mutex> lock(users_mutex);

            if (registered_users.find(username) != registered_users.end())
            {
                string reply =
                    "Username already taken. "
                    "Select another one.\n";

                send_message(client_fd, reply);

                continue;
            }

            registered_users[username] = client_ip;
            client_sockets[username] = client_fd;
            chat_partner[username] = "";

            registered = true;
        }

    string reply =
            "Successfully registered as " +
            username + "\n";

        send_message(client_fd, reply);

        {
            lock_guard<mutex> lock(cout_mutex);
            cout << "User registered: " << username << " -> " << client_ip << endl;
        }
    }

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));

        int bytes_received = recv( client_fd, buffer, sizeof(buffer) - 1, 0);

        if (bytes_received < 0){
            perror("Receive failed");
            break;
        }

        if (bytes_received == 0){
            lock_guard<mutex> lock(cout_mutex);

            cout << "Client disconnected: " << username
                 << " (" << client_ip << ")" << endl;

            break;
        }

        buffer[bytes_received] = '\0';
        string message(buffer);
        message = trim_message(message);

        if (message == "#register" ||
            message.rfind("#register ", 0) == 0)
        {
            send_message(client_fd,
                         "You are already registered as " + username + ".\n");
            continue;
        }

        // @username message
        if (!message.empty() &&
            message[0] == '@')
        {
            size_t space_pos = message.find(' ');

            if (space_pos != string::npos)
            {
                string target_username =
                    message.substr(1, space_pos - 1);

                string actual_message =
                    message.substr(space_pos + 1);

                int target_fd = -1;

                {
                    lock_guard<mutex> lock(users_mutex);

                    auto it =
                        client_sockets.find(target_username);

                    if (it != client_sockets.end())
                    {
                        target_fd = it->second;
                    }
                }

                // Target user does not exist
                if (target_fd == -1)
                {
                    string reply =
                        "User " + target_username + " is not online.\n";

                    send_message(client_fd, reply);

                    continue;
                }

                string forwarded_message =
                    "You received this from client " +
                    username + ": " +
                    actual_message + "\n";

                send_message(
                    target_fd,
                    forwarded_message);

                {
                    lock_guard<mutex> lock(cout_mutex);

                    cout << username
                         << " -> "
                         << target_username
                         << ": "
                         << actual_message
                         << endl;
                }

                chat_partner[username] = target_username;

                continue;
            }
        }

        // /chat username

        if (message.rfind("/chat ", 0) == 0)
        {
            string target_username =
                message.substr(6);

            bool user_exists = false;

            {
                lock_guard<mutex> lock(users_mutex);

                if (client_sockets.find(target_username) != client_sockets.end())
                {
                    user_exists = true;
                }

                if (user_exists)
                {
                    chat_partner[username] = target_username;
                }
            }

            if (!user_exists)
            {
                string reply =
                    "User " +
                    target_username +
                    " is not online.\n";

                send_message(client_fd, reply);
            }

            continue;
        }

        // /who
        if (message == "/who")
        {
            string reply = "Online users:\n";

            {
                lock_guard<mutex> lock(users_mutex);

                for (const auto &user : registered_users)
                {
                    reply += "- " + user.first + "\n";
                }
            }

            send_message(client_fd, reply);

            continue;
        }

        // /quit

        if (message == "/quit")
        {
            break;
        }

        string target_username = "";

        {
            lock_guard<mutex> lock(users_mutex);

            target_username =
                chat_partner[username];
        }

        // No chatting partner selected
        if (target_username.empty())
        {
            string reply =
                "No chatting partner selected. "
                "Use /chat <username> to select one.\n";

            send_message(client_fd, reply);

            continue;
        }

        int target_fd = -1;

        {
            lock_guard<mutex> lock(users_mutex);

            auto it =
                client_sockets.find(target_username);

            if (it != client_sockets.end())
            {
                target_fd = it->second;
            }
        }

        // Target disconnected
        if (target_fd == -1)
        {
            string reply =
                "User " +
                target_username +
                " is no longer online.\n";

            send_message(client_fd, reply);

            continue;
        }

        // Send plain text to selected partner
        string forwarded_message =
            "You received this from client " +
            username +
            ": " +
            message +
            "\n";

        send_message(
            target_fd,
            forwarded_message);

        {
            lock_guard<mutex> lock(cout_mutex);

            cout << username
                 << " -> "
                 << target_username
                 << ": "
                 << message
                 << endl;
        }
    }


    {
        lock_guard<mutex> lock(users_mutex);

        // Remove this user
        registered_users.erase(username);
        client_sockets.erase(username);
        chat_partner.erase(username);

        // Remove this user as a chat partner
        for (auto &entry : chat_partner)
        {
            if (entry.second == username)
            {
                entry.second = "";
            }
        }
    }

    close(client_fd);
}


int main()
{
    int server_fd = socket(AF_INET, SOCK_STREAM,0);

    if (server_fd < 0)
    {
        perror("Socket creation failed");
        return 1;
    }

    // Allow reuse of port
    int opt = 1;

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(server_fd);
        return 1;
    }

    sockaddr_in server_addr{};

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(
            server_fd,
            (struct sockaddr *)&server_addr,
            sizeof(server_addr)) < 0)
    {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    cout << "Server bound to port " << SERVER_PORT << endl;

    if (listen(server_fd, 2) < 0)
    {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    cout << "Server listening..." << endl;


    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_len =
            sizeof(client_addr);

        int client_fd = accept(
            server_fd,
            (struct sockaddr *)&client_addr,
            &client_len);

        if (client_fd < 0)
        {
            perror("Accept failed");
            continue;
        }

        string client_ip =
            inet_ntoa(client_addr.sin_addr);

        cout << "New client connected: "
             << client_ip << endl;

        // Create separate thread
        thread(
            handle_client,
            client_fd,
            client_ip)
            .detach();
    }

    close(server_fd);

    return 0;
}