// SPDX-License-Identifier: GPL-3.0-only

#include "tls_client.hpp"

#include <poll.h>

#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

namespace inspector {
namespace {
void require(int result, const char* message)
{
    if (result != WOLFSSL_SUCCESS)
        throw Error(ErrorKind::Tls, message, result);
}
} // namespace

TlsClient::TlsClient(const Options& options, int fd)
{
    context_.reset(wolfSSL_CTX_new(options.tls == "1.3"
                                       ? wolfTLSv1_3_client_method()
                                       : wolfTLSv1_2_client_method()));
    if (!context_)
        throw Error(ErrorKind::Tls,
                    "Cannot create version-specific TLS context");
    wolfSSL_CTX_set_verify(context_.get(), WOLFSSL_VERIFY_PEER, nullptr);
    const char* ca = options.ca_file.empty()
                         ? "/etc/ssl/certs/ca-certificates.crt"
                         : options.ca_file.c_str();
    require(wolfSSL_CTX_load_verify_locations(context_.get(), ca, nullptr),
            "Cannot load CA file (use --ca-file)");
    session_.reset(wolfSSL_new(context_.get()));
    if (!session_)
        throw Error(ErrorKind::Tls, "Cannot create TLS session");
    require(wolfSSL_check_domain_name(session_.get(), options.hostname.c_str()),
            "Cannot enable hostname verification");
    require(wolfSSL_UseSNI(
                session_.get(), WOLFSSL_SNI_HOST_NAME, options.hostname.data(),
                static_cast<unsigned short>(options.hostname.size())),
            "Cannot set SNI");
    require(wolfSSL_set_fd(session_.get(), fd), "Cannot attach socket");
    wolfSSL_set_using_nonblock(session_.get(), 1);
}

void TlsClient::handshake(Deadline deadline)
{
    for (;;) {
        if (std::chrono::steady_clock::now() >= deadline)
            throw Error(ErrorKind::Timeout, "TLS deadline exceeded");
        const int result = wolfSSL_connect(session_.get());
        if (result == WOLFSSL_SUCCESS)
            return;
        const int error = wolfSSL_get_error(session_.get(), result);
        if (error == WOLFSSL_ERROR_WANT_READ ||
            error == WOLFSSL_ERROR_WANT_WRITE) {
            wait_socket(wolfSSL_get_fd(session_.get()),
                        error == WOLFSSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                        deadline);
            continue;
        }
        char message[256]{};
        wolfSSL_ERR_error_string_n(static_cast<unsigned long>(error), message,
                                   sizeof(message));
        throw Error(classify_tls_error(error),
                    std::string("TLS handshake: ") + message, error);
    }
}

ErrorKind classify_tls_error(int code)
{
    switch (code) {
        case ASN_AFTER_DATE_E:
            return ErrorKind::Expired;
        case ASN_BEFORE_DATE_E:
            return ErrorKind::NotYetValid;
        case DOMAIN_NAME_MISMATCH:
            return ErrorKind::HostnameMismatch;
        // No signer may mean either a missing intermediate or an untrusted
        // root.
        case ASN_NO_SIGNER_E:
        case ASN_SIG_CONFIRM_E:
        case VERIFY_CERT_ERROR:
            return ErrorKind::InvalidChain;
        case ASN_SELF_SIGNED_E:
            return ErrorKind::UntrustedCa;
        default:
            return ErrorKind::Tls;
    }
}
} // namespace inspector
