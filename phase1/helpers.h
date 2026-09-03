#pragma once

#include <string>
#include <sys/socket.h>
#include <unistd.h>

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