// SPDX-License-Identifier: GPL-3.0-only

#include "result_formatter.hpp"

#include <iostream>

#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

using namespace inspector;

int main()
{
    try {
        auto check = [](bool value) {
            if (!value)
                throw std::runtime_error(
                    "certificate/formatter assertion failed");
        };
        check(classify_tls_error(ASN_AFTER_DATE_E) == ErrorKind::Expired);
        check(classify_tls_error(ASN_BEFORE_DATE_E) == ErrorKind::NotYetValid);
        check(classify_tls_error(DOMAIN_NAME_MISMATCH) ==
              ErrorKind::HostnameMismatch);
        check(classify_tls_error(ASN_NO_SIGNER_E) == ErrorKind::InvalidChain);
        check(classify_tls_error(-123456) == ErrorKind::Tls);
        check(read_certificate(nullptr).subject == "N/A");
        Result r;
        r.options.hostname = "localhost";
        r.certificate.subject = "quote\" slash\\ newline\n\033";
        r.certificate.san = {std::string("DNS: a\0b", 8)};
        auto json = format_json(r);
        check(json.find("quote\\\" slash\\\\ newline\\u000a\\u001b") !=
              std::string::npos);
        check(json.find("\\u0000") != std::string::npos);
        check(json.find("\"public_key_bits\":null") != std::string::npos);
        check(json.find("\"overall\":\"FAIL\"") != std::string::npos);
        auto text = format_text(r);
        check(text.find("\\x1b") != std::string::npos);
        check(text.find("Overall Result    : FAIL") != std::string::npos);
        r.certificate.san.clear();
        check(format_text(r).find("[Subject Alternative Names]\nN/A\n") !=
              std::string::npos);
        for (int i = 0; i < 10; ++i)
            r.certificate.san.push_back("DNS: san" + std::to_string(i) +
                                        ".example");
        check(format_text(r).find("omitted") == std::string::npos);
        r.certificate.san.push_back("DNS: san10.example");
        text = format_text(r);
        check(text.find("DNS: san9.example\n") != std::string::npos);
        check(text.find("DNS: san10.example") == std::string::npos);
        check(text.find("1 SAN entries omitted (showing 10 of 11; use "
                        "--all-sans to show all)") != std::string::npos);
        check(format_json(r).find("DNS: san10.example") != std::string::npos);
        r.options.all_sans = true;
        text = format_text(r);
        check(text.find("DNS: san10.example\n") != std::string::npos);
        check(text.find("omitted") == std::string::npos);
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
