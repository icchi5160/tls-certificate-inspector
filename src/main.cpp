// SPDX-License-Identifier: GPL-3.0-only

#include "certificate_inspector.hpp"
#include "result_formatter.hpp"

#include <csignal>
#include <iostream>

int main(int argc, char** argv)
{
    using namespace inspector;
    std::signal(SIGPIPE, SIG_IGN);
    bool json = false;
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--json")
            json = true;
    try {
        auto options = parse_arguments(argc, argv);
        if (options.help) {
            if (options.json)
                std::cout << "{\"usage\":\"tls-inspector <hostname> [--port N] "
                             "[--tls 1.2|1.3] "
                             "[--ca-file PATH] [--timeout N] [--json] "
                             "[--all-sans] [--help]\"}\n";
            else
                std::cout << usage();
            return 0;
        }
        auto result = inspect(options);
        std::cout << (options.json ? format_json(result) : format_text(result));
        if (result.overall == "PASS")
            return 0;
        std::cerr << result.error_category << ": " << result.error_message
                  << " (wolfSSL code " << result.native_code << ")\n";
        return exit_code(result.failure_kind);
    } catch (const Error& error) {
        Result result;
        result.error_category = error_name(error.kind);
        result.error_message = error.what();
        if (json)
            std::cout << format_json(result);
        std::cerr << result.error_category << ": " << error.what() << '\n';
        return exit_code(error.kind);
    } catch (const std::exception& error) {
        Result result;
        result.error_category = "UNKNOWN_ERROR";
        result.error_message = error.what();
        if (json)
            std::cout << format_json(result);
        std::cerr << "UNKNOWN_ERROR: " << error.what() << '\n';
        return 6;
    }
}
