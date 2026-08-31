#pragma once

#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "aes_utils.h"
#include "dh_utils.h"

inline std::string trim_message(const std::string &message)
{
    std::string result = message;

    while (!result.empty() &&
           (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();

    return result;
}

inline bool send_plain(int fd, const std::string &message)
{
    size_t sent = 0;

    while (sent < message.size())
    {
        ssize_t n = send(fd, message.data() + sent,
                         message.size() - sent, 0);

        if (n <= 0)
            return false;

        sent += static_cast<size_t>(n);
    }

    return true;
}

// DH handshake messages are newline-delimited.
// Read exactly one line so the following binary AES-GCM
// packet cannot accidentally be consumed by this function.
inline bool recv_plain_line(int fd, std::string &line_out)
{
    line_out.clear();

    while (true)
    {
        char c;
        ssize_t n = recv(fd, &c, 1, 0);

        if (n <= 0)
            return false;

        if (c == '\n')
            break;

        line_out.push_back(c);

        if (line_out.size() > 4096)
            return false;
    }

    line_out = trim_message(line_out);
    return true;
}
