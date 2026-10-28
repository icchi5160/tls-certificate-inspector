// SPDX-License-Identifier: GPL-3.0-only

#include "tcp_connection.hpp"

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>

namespace inspector {
namespace {
struct Fd {
    int value;

    ~Fd()
    {
        if (value >= 0)
            ::close(value);
    }
};

struct Address {
    sockaddr_storage address;
    socklen_t length;
};

struct Reply {
    int error;
    unsigned count;
    std::array<Address, 16> addresses;
};

// A single-threaded resolver child isolates blocking libc/NSS resolution. The
// parent always kills and reaps it, including on timeout or an exception.
struct Resolver {
    pid_t pid;

    ~Resolver()
    {
        ::kill(pid, SIGKILL);
        while (::waitpid(pid, nullptr, 0) < 0 && errno == EINTR) {
        }
    }
};

Reply resolve(const Options& options, Deadline deadline)
{
    int pipes[2];
    if (::pipe2(pipes, O_CLOEXEC) < 0)
        throw Error(ErrorKind::Tcp, "Cannot create DNS pipe");
    Fd reader{pipes[0]}, writer{pipes[1]};
    const auto port = std::to_string(options.port);
    pid_t pid = ::fork();
    if (pid < 0)
        throw Error(ErrorKind::Tcp, "Cannot start DNS resolver");
    if (pid == 0) {
        ::close(reader.value);
        addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_NUMERICSERV;
        addrinfo* addresses = nullptr;
        Reply reply{};
        reply.error = ::getaddrinfo(options.hostname.c_str(), port.c_str(),
                                    &hints, &addresses);
        if (!reply.error) {
            for (auto* a = addresses; a && reply.count < reply.addresses.size();
                 a = a->ai_next) {
                if ((a->ai_family != AF_INET && a->ai_family != AF_INET6) ||
                    a->ai_addrlen > sizeof(sockaddr_storage))
                    continue;
                auto& target = reply.addresses[reply.count++];
                std::memcpy(&target.address, a->ai_addr, a->ai_addrlen);
                target.length = a->ai_addrlen;
            }
            ::freeaddrinfo(addresses);
        }
        const auto* data = reinterpret_cast<const char*>(&reply);
        std::size_t sent = 0;
        while (sent < sizeof(reply)) {
            ssize_t n =
                ::write(writer.value, data + sent, sizeof(reply) - sent);
            if (n < 0 && errno == EINTR)
                continue;
            if (n <= 0)
                ::_exit(1);
            sent += static_cast<std::size_t>(n);
        }
        ::_exit(0);
    }
    Resolver child{pid};
    ::close(writer.value);
    writer.value = -1;
    Reply reply{};
    std::size_t received = 0;
    while (received < sizeof(reply)) {
        wait_socket(reader.value, POLLIN, deadline);
        ssize_t n =
            ::read(reader.value, reinterpret_cast<char*>(&reply) + received,
                   sizeof(reply) - received);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            throw Error(ErrorKind::Tcp, "DNS resolver terminated unexpectedly");
        received += static_cast<std::size_t>(n);
    }
    if (reply.error)
        throw Error(ErrorKind::Tcp,
                    std::string("DNS: ") + gai_strerror(reply.error));
    if (!reply.count)
        throw Error(ErrorKind::Tcp, "DNS returned no usable addresses");
    return reply;
}
} // namespace

void wait_socket(int fd, short events, Deadline deadline)
{
    for (;;) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now())
                .count();
        if (remaining <= 0)
            throw Error(ErrorKind::Timeout, "DNS/TCP/TLS deadline exceeded");
        pollfd p{fd, events, 0};
        int n = ::poll(&p, 1, static_cast<int>(remaining));
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            throw Error(ErrorKind::Tcp,
                        std::string("poll: ") + std::strerror(errno));
        if (n == 0)
            throw Error(ErrorKind::Timeout, "DNS/TCP/TLS deadline exceeded");
        if (p.revents & POLLNVAL)
            throw Error(ErrorKind::Tcp, "Invalid socket");
        return;
    }
}

TcpConnection::TcpConnection(const Options& options, Deadline deadline)
{
    const Reply reply = resolve(options, deadline);
    std::string last = "No reachable address";
    for (unsigned i = 0; i < reply.count; ++i) {
        const auto& a = reply.addresses[i];
        Fd socket{::socket(a.address.ss_family,
                           SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
        if (socket.value < 0) {
            last = std::strerror(errno);
            continue;
        }
        int n =
            ::connect(socket.value,
                      reinterpret_cast<const sockaddr*>(&a.address), a.length);
        if (n < 0 && errno == EINPROGRESS) {
            wait_socket(socket.value, POLLOUT, deadline);
            int error = 0;
            socklen_t length = sizeof(error);
            if (::getsockopt(socket.value, SOL_SOCKET, SO_ERROR, &error,
                             &length) < 0)
                error = errno;
            if (error) {
                last = std::strerror(error);
                continue;
            }
        } else if (n < 0) {
            last = std::strerror(errno);
            continue;
        }
        fd_ = std::exchange(socket.value, -1);
        return;
    }
    throw Error(ErrorKind::Tcp, "TCP connect: " + last);
}

TcpConnection::~TcpConnection()
{
    if (fd_ >= 0)
        ::close(fd_);
}

TcpConnection::TcpConnection(TcpConnection&& other) noexcept
    : fd_(std::exchange(other.fd_, -1))
{
}

TcpConnection& TcpConnection::operator=(TcpConnection&& other) noexcept
{
    if (this != &other) {
        if (fd_ >= 0)
            ::close(fd_);
        fd_ = std::exchange(other.fd_, -1);
    }
    return *this;
}
} // namespace inspector
