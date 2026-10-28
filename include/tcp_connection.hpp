// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include "certificate_info.hpp"

#include <chrono>

namespace inspector {
using Deadline = std::chrono::steady_clock::time_point;
void wait_socket(int fd, short events, Deadline deadline);

class TcpConnection {
    int fd_ = -1;

  public:
    TcpConnection(const Options& options, Deadline deadline);
    ~TcpConnection();
    TcpConnection(const TcpConnection&) = delete;
    TcpConnection& operator=(const TcpConnection&) = delete;
    TcpConnection(TcpConnection&& other) noexcept;
    TcpConnection& operator=(TcpConnection&& other) noexcept;

    int fd() const noexcept
    {
        return fd_;
    }
};
} // namespace inspector
