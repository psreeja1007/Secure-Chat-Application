#pragma once

#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "aes_utils.h"
#include "dh_utils.h"

inline std::string trim_message(const std::string &message) {
    std::string result = message;
    while (!result.empty() && (result.back() == '\n' || result.back() == '\r'))
        result.pop_back();
    return result;
}

inline bool send_plain(int fd, const std::string &message) {
    return aesgcm::send_all(fd,
        reinterpret_cast<const unsigned char *>(message.data()), message.size());
}

inline bool recv_plain_line(int fd, std::string &line_out) {
    line_out.clear();
    char c;
    while (true) {
        ssize_t n = recv(fd, &c, 1, 0);
        if (n <= 0) return false;
        if (c == '\n') break;
        line_out.push_back(c);
        if (line_out.size() > 8192) return false;
    }
    line_out = trim_message(line_out);
    return true;
}
