// SPDX-License-Identifier: GPL-3.0-only

#include "result_formatter.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace inspector {
namespace {
// Escape all non-ASCII bytes as well as controls: output is valid JSON even
// when an X.509 field contains bytes that are not valid UTF-8.
std::string quote(const std::string& value)
{
    std::ostringstream out;
    out << '"';
    for (unsigned char c : value) {
        if (c == '"' || c == '\\')
            out << '\\' << static_cast<char>(c);
        else if (c < 0x20 || c >= 0x7f)
            out << "\\u00" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(c);
        else
            out << static_cast<char>(c);
    }
    out << '"';
    return out.str();
}

std::string safe(const std::string& value)
{
    std::ostringstream out;
    for (unsigned char c : value) {
        if (c < 0x20 || c >= 0x7f)
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned>(c);
        else
            out << static_cast<char>(c);
    }
    return out.str();
}
} // namespace

std::string format_json(const Result& r)
{
    const auto& c = r.certificate;
    std::ostringstream o;
    o << "{\"connection\":{\"hostname\":" << quote(r.options.hostname)
      << ",\"port\":" << r.options.port
      << ",\"tls_version\":" << quote(r.tls_version)
      << ",\"cipher_suite\":" << quote(r.cipher_suite) << "},\"certificate\":{"
      << "\"subject\":" << quote(c.subject) << ",\"issuer\":" << quote(c.issuer)
      << ",\"serial_number\":" << quote(c.serial_number)
      << ",\"not_before\":" << quote(c.not_before)
      << ",\"not_after\":" << quote(c.not_after) << ",\"san\":[";
    for (std::size_t i = 0; i < c.san.size(); ++i) {
        if (i)
            o << ',';
        o << quote(c.san[i]);
    }
    o << "],\"public_key_algorithm\":" << quote(c.public_key_algorithm)
      << ",\"public_key_bits\":"
      << (c.public_key_bits > 0 ? std::to_string(c.public_key_bits) : "null")
      << ",\"signature_algorithm\":" << quote(c.signature_algorithm)
      << ",\"sha256_fingerprint\":" << quote(c.sha256_fingerprint)
      << "},\"verification\":{\"chain\":" << quote(r.chain)
      << ",\"hostname\":" << quote(r.hostname)
      << ",\"validity_period\":" << quote(r.validity)
      << ",\"trust_anchor\":" << quote(r.trust)
      << ",\"wolfssl_combined\":" << quote(r.combined)
      << ",\"detail\":\"Chain, validity and trust are checked together by "
         "wolfSSL; separate "
         "results are unavailable\",\"overall\":"
      << quote(r.overall) << "},\"error\":";
    if (r.error_category.empty())
        o << "null";
    else
        o << "{\"category\":" << quote(r.error_category)
          << ",\"message\":" << quote(r.error_message)
          << ",\"native_code\":" << r.native_code << '}';
    o << "}\n";
    return o.str();
}

std::string format_text(const Result& r)
{
    const auto& c = r.certificate;
    std::ostringstream o;
    o << "TLS Certificate "
         "Inspector\n========================================\n\n[Connection]"
         "\nHostname          : "
      << safe(r.options.hostname) << "\nPort              : " << r.options.port
      << "\nTLS Version       : " << safe(r.tls_version)
      << "\nCipher Suite      : " << safe(r.cipher_suite)
      << "\n\n[Certificate]\nSubject           : " << safe(c.subject)
      << "\nIssuer            : " << safe(c.issuer)
      << "\nSerial Number     : " << safe(c.serial_number)
      << "\nValid From        : " << safe(c.not_before)
      << "\nValid Until       : " << safe(c.not_after)
      << "\nPublic Key        : " << safe(c.public_key_algorithm) << ' '
      << (c.public_key_bits > 0 ? std::to_string(c.public_key_bits) + "-bit"
                                : "N/A")
      << "\nSignature         : " << safe(c.signature_algorithm)
      << "\nSHA-256 Fingerprint: " << safe(c.sha256_fingerprint)
      << "\n\n[Subject Alternative Names]\n";
    if (c.san.empty())
        o << "N/A\n";
    const auto shown = r.options.all_sans
                           ? c.san.size()
                           : std::min(c.san.size(), std::size_t{10});
    for (std::size_t i = 0; i < shown; ++i)
        o << safe(c.san[i]) << '\n';
    if (shown < c.san.size())
        o << "... " << c.san.size() - shown << " SAN entries omitted (showing "
          << shown << " of " << c.san.size()
          << "; use --all-sans to show all)\n";
    o << "\n[Verification]\nChain / validity / trust (wolfSSL): " << r.combined
      << "\nCertificate Chain : " << r.chain
      << "\nValidity Period   : " << r.validity
      << "\nTrust Anchor      : " << r.trust
      << "\nNOT_CHECKED means no separate API result; see combined "
         "verification above."
      << "\nHostname          : " << r.hostname
      << "\nOverall Result    : " << r.overall << '\n';
    if (!r.error_category.empty())
        o << "Error             : " << safe(r.error_category) << '\n';
    return o.str();
}

std::string usage()
{
    return "Usage: tls-inspector <hostname> [options]\n"
           "  --port N         TCP port, 1..65535 (default: 443)\n"
           "  --tls 1.2|1.3    Exact TLS version (default: 1.3)\n"
           "  --ca-file PATH   PEM trust anchors (default: Ubuntu system "
           "bundle)\n"
           "  --timeout N      Total DNS/TCP/TLS deadline, 1..3600 seconds "
           "(default: 5)\n"
           "  --json           JSON output\n"
           "  --all-sans       Show all SANs in text output (default: first "
           "10; JSON always "
           "includes all)\n"
           "  --help           Show help\n"
           "Hostnames use ASCII DNS labels (IDNs: A-labels); IP literals are "
           "unsupported.\n";
}
} // namespace inspector
