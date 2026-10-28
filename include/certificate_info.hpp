// SPDX-License-Identifier: GPL-3.0-only

#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

namespace inspector {
enum class ErrorKind {
    Arguments,
    Tcp,
    Timeout,
    UntrustedCa,
    Expired,
    NotYetValid,
    HostnameMismatch,
    InvalidChain,
    Tls,
    Unknown
};

const char* error_name(ErrorKind kind);
int exit_code(ErrorKind kind);

struct Error : std::runtime_error {
    ErrorKind kind;
    int native_code;

    Error(ErrorKind k, const std::string& message, int code = 0)
        : std::runtime_error(message), kind(k), native_code(code)
    {
    }
};

struct Options {
    std::string hostname, ca_file;
    int port = 443, timeout = 5;
    std::string tls = "1.3";
    bool json = false, help = false, all_sans = false;
};

struct CertificateInfo {
    std::string subject = "N/A", issuer = "N/A", serial_number = "N/A";
    std::string not_before = "N/A", not_after = "N/A";
    std::vector<std::string> san;
    std::string public_key_algorithm = "N/A", signature_algorithm = "N/A";
    int public_key_bits = 0;
    std::string sha256_fingerprint = "N/A";
};

struct Result {
    Options options;
    std::string tls_version = "N/A", cipher_suite = "N/A";
    CertificateInfo certificate;
    std::string chain = "NOT_CHECKED", validity = "NOT_CHECKED",
                trust = "NOT_CHECKED";
    std::string combined = "NOT_CHECKED", hostname = "NOT_CHECKED",
                overall = "FAIL";
    std::string error_category, error_message;
    int native_code = 0;
    ErrorKind failure_kind = ErrorKind::Unknown;
};

CertificateInfo read_certificate(WOLFSSL_X509* cert);
ErrorKind classify_tls_error(int code);
} // namespace inspector
