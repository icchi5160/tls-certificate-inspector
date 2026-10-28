// SPDX-License-Identifier: GPL-3.0-only

#include "certificate_info.hpp"

#include <iomanip>
#include <arpa/inet.h>
#include <memory>
#include <sstream>

#include <wolfssl/openssl/evp.h>
#include <wolfssl/openssl/x509v3.h>
#include <wolfssl/wolfcrypt/sha256.h>

namespace inspector {
namespace {
std::string hex(const unsigned char* bytes, int size)
{
    std::ostringstream out;
    out << std::hex << std::uppercase << std::setfill('0');
    for (int i = 0; i < size; ++i) {
        if (i)
            out << ':';
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
}

std::string name(WOLFSSL_X509_NAME* value)
{
    if (!value)
        return "N/A";
    std::unique_ptr<char, decltype(&wolfSSL_OPENSSL_free)> text(
        wolfSSL_X509_NAME_oneline(value, nullptr, 0), wolfSSL_OPENSSL_free);
    return text ? std::string(text.get()) : "N/A";
}

std::string date(WOLFSSL_ASN1_TIME* value)
{
    char buffer[80]{};
    return value && wolfSSL_ASN1_TIME_to_string(value, buffer, sizeof(buffer))
               ? buffer
               : "N/A";
}
} // namespace

CertificateInfo read_certificate(WOLFSSL_X509* cert)
{
    CertificateInfo info;
    if (!cert)
        return info;
    info.subject = name(wolfSSL_X509_get_subject_name(cert));
    info.issuer = name(wolfSSL_X509_get_issuer_name(cert));
    unsigned char serial[64]{};
    int length = sizeof(serial);
    if (wolfSSL_X509_get_serial_number(cert, serial, &length) ==
            WOLFSSL_SUCCESS &&
        length > 0)
        info.serial_number = hex(serial, length);
    info.not_before = date(wolfSSL_X509_get_notBefore(cert));
    info.not_after = date(wolfSSL_X509_get_notAfter(cert));
    std::unique_ptr<WOLFSSL_GENERAL_NAMES,
                    decltype(&wolfSSL_GENERAL_NAMES_free)>
        names(static_cast<WOLFSSL_GENERAL_NAMES*>(wolfSSL_X509_get_ext_d2i(
                  cert, NID_subject_alt_name, nullptr, nullptr)),
              wolfSSL_GENERAL_NAMES_free);
    if (names) {
        for (int i = 0; i < wolfSSL_sk_GENERAL_NAME_num(names.get()); ++i) {
            auto* entry = wolfSSL_sk_GENERAL_NAME_value(names.get(), i);
            if (!entry)
                continue;
            // Length-aware strings preserve embedded NULs for safe output
            // escaping.
            if (entry->type == GEN_DNS || entry->type == GEN_EMAIL ||
                entry->type == GEN_URI) {
                auto* value = entry->d.ia5;
                int size = wolfSSL_ASN1_STRING_length(value);
                auto* bytes = wolfSSL_ASN1_STRING_data(value);
                if (bytes && size >= 0)
                    info.san.push_back(
                        std::string(entry->type == GEN_DNS     ? "DNS: "
                                    : entry->type == GEN_EMAIL ? "EMAIL: "
                                                               : "URI: ") +
                        std::string(reinterpret_cast<char*>(bytes),
                                    static_cast<std::size_t>(size)));
            } else if (entry->type == GEN_IPADD) {
                auto* value = entry->d.iPAddress;
                const int size = wolfSSL_ASN1_STRING_length(value);
                auto* bytes = wolfSSL_ASN1_STRING_data(value);
                char address[INET6_ADDRSTRLEN]{};
                if (bytes && (size == 4 || size == 16) &&
                    ::inet_ntop(size == 4 ? AF_INET : AF_INET6, bytes, address,
                                sizeof(address)))
                    info.san.push_back(std::string("IP: ") + address);
                else
                    info.san.push_back("N/A (IP SAN)");
            } else
                info.san.push_back("N/A (SAN type " +
                                   std::to_string(entry->type) + ")");
        }
    }
    // 5.6.6's EVP adapter defaults unknown key OIDs to EC. Only call it for
    // algorithms positively identified by the certificate's public-key OID.
    int type = wolfSSL_X509_get_pubkey_type(cert);
    if (type == RSAk || type == ECDSAk) {
        std::unique_ptr<WOLFSSL_EVP_PKEY, decltype(&wolfSSL_EVP_PKEY_free)> key(
            wolfSSL_X509_get_pubkey(cert), wolfSSL_EVP_PKEY_free);
        if (key) {
            info.public_key_algorithm = type == RSAk ? "RSA" : "EC";
            info.public_key_bits = wolfSSL_EVP_PKEY_bits(key.get());
        }
    }
    const char* signature =
        wolfSSL_OBJ_nid2ln(wolfSSL_X509_get_signature_nid(cert));
    if (signature)
        info.signature_algorithm = signature;
    int der_size = 0;
    const unsigned char* der = wolfSSL_X509_get_der(cert, &der_size);
    unsigned char digest[WC_SHA256_DIGEST_SIZE]{};
    if (der && der_size > 0 &&
        wc_Sha256Hash(der, static_cast<word32>(der_size), digest) == 0)
        info.sha256_fingerprint = hex(digest, sizeof(digest));
    return info;
}

const char* error_name(ErrorKind kind)
{
    switch (kind) {
        case ErrorKind::Arguments:
            return "ARGUMENT_ERROR";
        case ErrorKind::Tcp:
            return "TCP_ERROR";
        case ErrorKind::Timeout:
            return "TIMEOUT";
        case ErrorKind::UntrustedCa:
            return "UNTRUSTED_CA";
        case ErrorKind::Expired:
            return "EXPIRED_CERTIFICATE";
        case ErrorKind::NotYetValid:
            return "NOT_YET_VALID";
        case ErrorKind::HostnameMismatch:
            return "HOSTNAME_MISMATCH";
        case ErrorKind::InvalidChain:
            return "INVALID_CERTIFICATE_CHAIN";
        case ErrorKind::Tls:
            return "TLS_ERROR";
        case ErrorKind::Unknown:
            return "UNKNOWN_ERROR";
    }
    return "UNKNOWN_ERROR";
}

int exit_code(ErrorKind kind)
{
    switch (kind) {
        case ErrorKind::Arguments:
            return 2;
        case ErrorKind::UntrustedCa:
        case ErrorKind::Expired:
        case ErrorKind::NotYetValid:
        case ErrorKind::HostnameMismatch:
        case ErrorKind::InvalidChain:
            return 3;
        case ErrorKind::Tcp:
        case ErrorKind::Tls:
            return 4;
        case ErrorKind::Timeout:
            return 5;
        default:
            return 6;
    }
}
} // namespace inspector
