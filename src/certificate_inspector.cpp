// SPDX-License-Identifier: GPL-3.0-only

#include "certificate_inspector.hpp"
#include "tls_client.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <memory>

namespace inspector {
namespace {
int number(const std::string& value, int max, const std::string& option)
{
    int result = 0;
    auto parsed =
        std::from_chars(value.data(), value.data() + value.size(), result);
    if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size() ||
        result < 1 || result > max)
        throw Error(ErrorKind::Arguments, option +
                                              " must be an integer in 1.." +
                                              std::to_string(max));
    return result;
}
} // namespace

Options parse_arguments(int argc, char** argv)
{
    Options options;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") {
            options.help = true;
            continue;
        }
        if (arg == "--json") {
            options.json = true;
            continue;
        }
        if (arg == "--all-sans") {
            options.all_sans = true;
            continue;
        }
        if (arg == "--port" || arg == "--tls" || arg == "--ca-file" ||
            arg == "--timeout") {
            if (++i >= argc)
                throw Error(ErrorKind::Arguments, "Missing value for " + arg);
            std::string value = argv[i];
            if (arg == "--port")
                options.port = number(value, 65535, arg);
            if (arg == "--timeout")
                options.timeout = number(value, 3600, arg);
            if (arg == "--tls") {
                if (value != "1.2" && value != "1.3")
                    throw Error(ErrorKind::Arguments,
                                "--tls must be 1.2 or 1.3");
                options.tls = value;
            }
            if (arg == "--ca-file") {
                if (value.empty() || value.front() == '-')
                    throw Error(ErrorKind::Arguments,
                                "Invalid --ca-file value");
                options.ca_file = value;
            }
        } else if (!arg.empty() && arg.front() == '-')
            throw Error(ErrorKind::Arguments, "Unknown option: " + arg);
        else if (!options.hostname.empty())
            throw Error(ErrorKind::Arguments, "Only one hostname is allowed");
        else
            options.hostname = arg;
    }
    if (options.help)
        return options;
    if (options.hostname.empty() || options.hostname.size() > 253)
        throw Error(ErrorKind::Arguments,
                    "A DNS hostname of 1..253 characters is required");
    unsigned char address[16];
    if (::inet_pton(AF_INET, options.hostname.c_str(), address) == 1 ||
        ::inet_pton(AF_INET6, options.hostname.c_str(), address) == 1)
        throw Error(ErrorKind::Arguments,
                    "Use a DNS hostname; IP literal identity verification is "
                    "not supported");
    // Accept ASCII DNS labels only; callers must supply IDNs as A-labels.
    if (options.hostname.back() == '.')
        options.hostname.pop_back();
    std::size_t start = 0;
    for (std::size_t i = 0; i <= options.hostname.size(); ++i) {
        if (i == options.hostname.size() || options.hostname[i] == '.') {
            const auto length = i - start;
            if (!length || length > 63 || options.hostname[start] == '-' ||
                options.hostname[i - 1] == '-')
                throw Error(ErrorKind::Arguments, "Invalid DNS label");
            start = i + 1;
        } else {
            const char c = options.hostname[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-'))
                throw Error(ErrorKind::Arguments,
                            "Hostname must contain ASCII DNS labels");
        }
    }
    return options;
}

Result inspect(const Options& options)
{
    Result result;
    result.options = options;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(options.timeout);
    try {
        TcpConnection tcp(options, deadline);

        // Resolve/fork before initializing wolfSSL; the CLI is single-threaded.
        struct Runtime {
            Runtime()
            {
                if (wolfSSL_Init() != WOLFSSL_SUCCESS)
                    throw Error(ErrorKind::Unknown,
                                "wolfSSL initialization failed");
            }

            ~Runtime()
            {
                wolfSSL_Cleanup();
            }
        } runtime;

        TlsClient tls(options, tcp.fd());
        tls.handshake(deadline);
        const std::string version = wolfSSL_get_version(tls.session());
        if (version != (options.tls == "1.3" ? "TLSv1.3" : "TLSv1.2"))
            throw Error(ErrorKind::Tls,
                        "Negotiated TLS version differs from request");
        std::unique_ptr<WOLFSSL_X509, decltype(&wolfSSL_X509_free)> certificate(
            wolfSSL_get_peer_certificate(tls.session()), wolfSSL_X509_free);
        if (!certificate)
            throw Error(ErrorKind::Unknown,
                        "Verified peer certificate unavailable");
        result.certificate = read_certificate(certificate.get());
        result.tls_version = version;
        result.cipher_suite = wolfSSL_get_cipher_name(tls.session());
        result.combined = result.hostname = result.overall = "PASS";
    } catch (const Error& error) {
        result.failure_kind = error.kind;
        result.error_category = error_name(error.kind);
        result.error_message = error.what();
        result.native_code = error.native_code;
        if (exit_code(error.kind) == 3) {
            if (error.kind == ErrorKind::HostnameMismatch)
                result.hostname = "FAIL";
            else
                result.combined = "FAIL";
            if (error.kind == ErrorKind::Expired ||
                error.kind == ErrorKind::NotYetValid)
                result.validity = "FAIL";
            if (error.kind == ErrorKind::InvalidChain)
                result.chain = "FAIL";
            if (error.kind == ErrorKind::UntrustedCa)
                result.trust = "FAIL";
        }
    }
    return result;
}
} // namespace inspector
