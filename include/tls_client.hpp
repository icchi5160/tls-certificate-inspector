// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include "tcp_connection.hpp"

#include <memory>

namespace inspector {
class TlsClient {
    struct ContextDeleter {
        void operator()(WOLFSSL_CTX* p) const
        {
            wolfSSL_CTX_free(p);
        }
    };

    struct SessionDeleter {
        void operator()(WOLFSSL* p) const
        {
            wolfSSL_free(p);
        }
    };

    std::unique_ptr<WOLFSSL_CTX, ContextDeleter> context_;
    std::unique_ptr<WOLFSSL, SessionDeleter> session_;

  public:
    TlsClient(const Options& options, int fd);
    void handshake(Deadline deadline);

    WOLFSSL* session() const noexcept
    {
        return session_.get();
    }
};
} // namespace inspector
