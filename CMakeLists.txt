# SPDX-License-Identifier: GPL-3.0-only

cmake_minimum_required(VERSION 3.16)
project(tls_certificate_inspector VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(ENABLE_SANITIZERS "Enable AddressSanitizer and UBSan" OFF)
find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h)
find_library(WOLFSSL_LIBRARY NAMES wolfssl)
if(NOT WOLFSSL_INCLUDE_DIR OR NOT WOLFSSL_LIBRARY)
    message(FATAL_ERROR "wolfSSL >= 5.9.4 development files missing. See README or run scripts/install-wolfssl.sh with an installation prefix (TLS 1.3, SNI, OPENSSL_EXTRA and KEEP_PEER_CERT required).")
endif()
add_library(wolfssl_system UNKNOWN IMPORTED)
set_target_properties(wolfssl_system PROPERTIES IMPORTED_LOCATION "${WOLFSSL_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}")
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_LIBRARIES wolfssl_system)
unset(WOLFSSL_FEATURES_AVAILABLE CACHE)
check_cxx_source_compiles("#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
#include <wolfssl/openssl/evp.h>
#if !defined(WOLFSSL_TLS13) || !defined(HAVE_SNI) || !defined(OPENSSL_EXTRA) || !defined(KEEP_PEER_CERT) || defined(NO_TLS12) || defined(WOLFSSL_NO_TLS12) || defined(NO_ASN_TIME_CHECK) || defined(NO_ASN_TIME) || defined(NO_CERTS)
#error Required wolfSSL features are disabled
#endif
#if LIBWOLFSSL_VERSION_HEX < 0x05009004
#error wolfSSL 5.9.4 or later is required
#endif
int main() { auto* m = wolfTLSv1_3_client_method(); (void)m; auto* n = wolfTLSv1_2_client_method(); (void)n; return 0; }" WOLFSSL_FEATURES_AVAILABLE)
if(NOT WOLFSSL_FEATURES_AVAILABLE)
    message(FATAL_ERROR "wolfSSL lacks required TLS 1.2/1.3, SNI, OPENSSL_EXTRA, KEEP_PEER_CERT, certificate date checks or version >= 5.9.4; see README or rebuild using scripts/install-wolfssl.sh.")
endif()
include(CheckCXXSourceRuns)
unset(WOLFSSL_VERSION_MATCHES CACHE)
check_cxx_source_runs("#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/version.h>
int main() { return wolfSSL_lib_version_hex() == LIBWOLFSSL_VERSION_HEX ? 0 : 1; }" WOLFSSL_VERSION_MATCHES)
if(NOT WOLFSSL_VERSION_MATCHES)
    message(FATAL_ERROR "wolfSSL runtime library does not match its headers or cannot run. Use a matching WOLFSSL_INCLUDE_DIR/WOLFSSL_LIBRARY pair and check the runtime library search path.")
endif()
add_library(inspector_core src/tcp_connection.cpp src/tls_client.cpp src/certificate_info.cpp src/certificate_inspector.cpp src/result_formatter.cpp)
target_include_directories(inspector_core PUBLIC include)
target_link_libraries(inspector_core PUBLIC wolfssl_system)
target_compile_options(inspector_core PRIVATE -Wall -Wextra -Wpedantic)
if(ENABLE_SANITIZERS)
    target_compile_options(inspector_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie)
    target_link_options(inspector_core PUBLIC -fsanitize=address,undefined -no-pie)
endif()
add_executable(tls-inspector src/main.cpp)
target_link_libraries(tls-inspector PRIVATE inspector_core)
target_compile_options(tls-inspector PRIVATE -Wall -Wextra -Wpedantic)
include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
install(TARGETS tls-inspector RUNTIME DESTINATION bin)
