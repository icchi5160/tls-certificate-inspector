<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Class Diagram

This diagram shows the main classes, data structures, and function groups in the current implementation. Some members, error types, and internal helpers are omitted for readability. Nodes marked `module` represent free functions grouped by source file, not C++ classes. All application types and functions shown belong to the `inspector` namespace.

```mermaid
classDiagram
    class Options {
        <<struct>>
        +string hostname
        +string ca_file
        +int port
        +int timeout
        +string tls
        +bool json
        +bool all_sans
    }

    class TcpConnection {
        -int fd_
        +TcpConnection(options, deadline)
        +~TcpConnection()
        +fd() int
    }

    class TlsClient {
        -unique_ptr context_
        -unique_ptr session_
        +TlsClient(options, fd)
        +handshake(deadline)
        +session() WOLFSSL*
    }

    class CertificateInfo {
        <<struct>>
        +string subject
        +string issuer
        +string serial_number
        +string not_before
        +string not_after
        +vector~string~ san
        +string public_key_algorithm
        +int public_key_bits
        +string signature_algorithm
        +string sha256_fingerprint
    }

    class Result {
        <<struct>>
        +Options options
        +CertificateInfo certificate
        +string tls_version
        +string cipher_suite
        +string combined
        +string hostname
        +string overall
        +string error_message
    }

    class certificate_inspector_cpp {
        <<module>>
        +parse_arguments(argc, argv) Options
        +inspect(options) Result
    }

    class certificate_info_cpp {
        <<module>>
        +read_certificate(cert) CertificateInfo
        +classify_tls_error(code) ErrorKind
    }

    class result_formatter_cpp {
        <<module>>
        +format_text(result) string
        +format_json(result) string
        +usage() string
    }

    Result *-- Options : 保持
    Result *-- CertificateInfo : 保持

    TcpConnection ..> Options : 設定を参照
    TlsClient ..> Options : 設定を参照

    certificate_inspector_cpp ..> TcpConnection : 生成
    certificate_inspector_cpp ..> TlsClient : 生成
    certificate_inspector_cpp ..> certificate_info_cpp : 解析を依頼
    certificate_inspector_cpp ..> Result : 作成して返す

    certificate_info_cpp ..> CertificateInfo : 作成して返す
    result_formatter_cpp ..> Result : 表示用に参照
```

`+` means public, `-` means private, `*--` indicates composition (ownership), and `..>` indicates a dependency. `TlsClient` receives the socket descriptor as an integer; it does not own a `TcpConnection`. The `inspect()` function manages both objects and their lifetimes.

## Viewing the Diagram

- **GitHub:** after publishing the repository, open this Markdown file in GitHub's rendered view. GitHub renders the fenced `mermaid` block as a diagram. See [GitHub's diagram documentation](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/creating-diagrams).
- **Browser:** open [Mermaid Live Editor](https://mermaid.live/) and paste the contents of the code block, from `classDiagram` through its final relationship. Omit the opening and closing Markdown fences. The editor previews the diagram and supports image export.
- **Editor:** use a Markdown preview with Mermaid support to open this file locally. A plain text editor displays the diagram source instead of rendering it.

The diagram is maintained manually. Update it when changing the implementation's types or relationships.
