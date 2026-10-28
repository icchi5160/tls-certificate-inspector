// SPDX-License-Identifier: GPL-3.0-only

#include "certificate_inspector.hpp"
#include "tcp_connection.hpp"

#include <iostream>
#include <vector>
#include <netdb.h>
#include <unistd.h>
#include <sys/wait.h>
#include <cerrno>

static bool delay_resolver = false;
extern "C" int __real_getaddrinfo(const char*, const char*, const addrinfo*,
                                  addrinfo**);

extern "C" int __wrap_getaddrinfo(const char* host, const char* service,
                                  const addrinfo* hints, addrinfo** result)
{
    if (delay_resolver)
        ::sleep(10);
    return __real_getaddrinfo(host, service, hints, result);
}

using namespace inspector;

namespace {
void check(bool condition, const char* message)
{
    if (!condition)
        throw std::runtime_error(message);
}

Options parse(std::initializer_list<const char*> args)
{
    std::vector<std::string> values;
    for (auto* v : args)
        values.emplace_back(v);
    std::vector<char*> pointers;
    for (auto& v : values)
        pointers.push_back(v.data());
    return parse_arguments(static_cast<int>(pointers.size()), pointers.data());
}
} // namespace

int main()
{
    try {
        auto defaults = parse({"cli", "localhost"});
        check(defaults.port == 443 && defaults.tls == "1.3" &&
                  defaults.timeout == 5,
              "defaults");
        auto custom =
            parse({"cli", "localhost", "--port", "8443", "--tls", "1.2",
                   "--timeout", "10", "--json", "--ca-file", "ca.pem"});
        check(custom.port == 8443 && custom.tls == "1.2" &&
                  custom.timeout == 10 && custom.json &&
                  custom.ca_file == "ca.pem",
              "custom options");
        check(parse({"cli", "--help"}).help, "help");
        check(!defaults.all_sans, "SAN display is limited by default");
        check(parse({"cli", "localhost", "--all-sans"}).all_sans,
              "all SANs option");
        check(parse({"cli", "localhost."}).hostname == "localhost",
              "trailing DNS dot");
        for (const auto& args : std::vector<std::vector<std::string>>{
                 {"cli"},
                 {"cli", "localhost", "--port", "0"},
                 {"cli", "localhost", "--port", "65536"},
                 {"cli", "localhost", "--port", "-1"},
                 {"cli", "localhost", "--port", "443x"},
                 {"cli", "localhost", "--port", "999999999999999999999"},
                 {"cli", "localhost", "--port"},
                 {"cli", "localhost", "--tls", "1.1"},
                 {"cli", "localhost", "--timeout", "0"},
                 {"cli", "localhost", "--timeout", "3601"},
                 {"cli", "localhost", "--unknown"},
                 {"cli", "localhost", "extra"},
                 {"cli", "bad/name"},
                 {"cli", "-bad"},
                 {"cli", "a..b"},
                 {"cli", "a-.b"},
                 {"cli", "127.0.0.1"},
                 {"cli", "::1"},
                 {"cli", "."}}) {
            auto copy = args;
            std::vector<char*> pointers;
            for (auto& s : copy)
                pointers.push_back(s.data());
            bool rejected = false;
            try {
                parse_arguments(static_cast<int>(copy.size()), pointers.data());
            } catch (const Error& e) {
                rejected = e.kind == ErrorKind::Arguments;
            }
            check(rejected, "invalid arguments accepted");
        }
        check(exit_code(ErrorKind::Arguments) == 2 &&
                  exit_code(ErrorKind::Expired) == 3 &&
                  exit_code(ErrorKind::Tcp) == 4 &&
                  exit_code(ErrorKind::Timeout) == 5,
              "exit codes");
        bool timed_out = false;
        try {
            TcpConnection connection(defaults,
                                     std::chrono::steady_clock::now() -
                                         std::chrono::seconds(1));
        } catch (const Error& e) {
            timed_out = e.kind == ErrorKind::Timeout;
        }
        check(timed_out, "resolver deadline");
        delay_resolver = true;
        timed_out = false;
        const auto start = std::chrono::steady_clock::now();
        try {
            TcpConnection connection(defaults,
                                     start + std::chrono::milliseconds(100));
        } catch (const Error& e) {
            timed_out = e.kind == ErrorKind::Timeout;
        }
        delay_resolver = false;
        check(timed_out, "blocking getaddrinfo deadline");
        check(std::chrono::steady_clock::now() - start <
                  std::chrono::seconds(2),
              "DNS timed out too late");
        check(::waitpid(-1, nullptr, WNOHANG) == -1 && errno == ECHILD,
              "resolver child was not reaped");
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
