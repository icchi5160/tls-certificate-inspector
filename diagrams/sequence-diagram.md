<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Sequence Diagrams

These diagrams describe the current CLI implementation. Participants represent objects or groups of free functions; they are not all C++ classes. The TLS message exchange is summarized rather than showing every TLS protocol message. Diagram labels are in Japanese to match the class diagram.

## Successful Inspection

This path assumes valid arguments without `--help`, successful certificate and hostname verification, and successful peer-certificate retrieval. `inspect()` uses one monotonic deadline for DNS, TCP and the handshake.

```mermaid
sequenceDiagram
    actor User as 利用者
    participant Main as main()
    participant Inspector as certificate_inspector.cpp
    participant TCP as TcpConnection
    participant TLS as TlsClient
    participant Wolf as wolfSSL
    participant Server as TLSサーバー
    participant Cert as read_certificate()
    participant Format as result_formatter.cpp

    User->>Main: hostname とオプションを指定して実行
    Main->>Inspector: parse_arguments(argc, argv)
    Inspector-->>Main: Options
    Main->>Inspector: inspect(options)
    Inspector->>Inspector: 共通の期限を設定

    Inspector->>TCP: コンストラクター(options, deadline)
    Note over TCP: 子プロセスで getaddrinfo()<br/>親は pipe を poll() し、子を必ず回収
    TCP->>Server: 解決したアドレスへ非ブロッキングTCP接続
    Note over TCP,Server: 必要に応じて poll() と SO_ERROR で完了を確認<br/>失敗したアドレスは期限内で次候補を試す
    Server-->>TCP: TCP接続成立
    TCP-->>Inspector: 接続済みソケットを所有するオブジェクト

    Inspector->>Wolf: wolfSSL_Init()
    Inspector->>TLS: コンストラクター(options, tcp.fd())
    TLS->>Wolf: 指定バージョン専用のコンテキストを作成
    TLS->>Wolf: WOLFSSL_VERIFY_PEER と CAファイルを設定
    TLS->>Wolf: セッションを作成
    TLS->>Wolf: wolfSSL_check_domain_name() でホスト名検証を設定
    TLS->>Wolf: wolfSSL_UseSNI() で接続先名を設定
    TLS->>Wolf: ソケットと非ブロッキング動作を設定
    TLS-->>Inspector: 初期化完了

    Inspector->>TLS: handshake(deadline)
    loop ハンドシェイクが成功するまで（期限内）
        TLS->>Wolf: wolfSSL_connect()
        Wolf->>Server: TLSハンドシェイクのメッセージを送信
        Server-->>Wolf: 証明書などのTLSメッセージを受信
        Note over Wolf: チェーン・有効期間・信頼先・ホスト名を検証<br/>SNIの送信とホスト名検証は別の処理
        Wolf-->>TLS: 成功 または WANT_READ / WANT_WRITE
        opt ソケットの読み書き待ちが必要
            TLS->>TLS: wait_socket() で poll()（残り時間まで）
        end
    end
    TLS-->>Inspector: 検証済みハンドシェイク完了

    Inspector->>Wolf: ネゴシエートされたTLSバージョンを取得
    Inspector->>Inspector: 要求したバージョンと一致するか確認
    Inspector->>Wolf: wolfSSL_get_peer_certificate()
    Wolf-->>Inspector: 所有権を持つLeaf証明書のコピー
    Inspector->>Cert: read_certificate(cert)
    Cert->>Wolf: Subject・SAN・公開鍵・DERなどを取得
    Wolf-->>Cert: 証明書の情報
    Cert->>Cert: wolfCryptでDERのSHA-256指紋を計算
    Cert-->>Inspector: CertificateInfo
    Inspector->>Wolf: TLSバージョンとCipher Suiteを取得
    Inspector->>Inspector: Resultに情報と検証結果を格納

    Note over Inspector,TCP: inspect()を抜ける際、RAIIで逆順に解放
    Inspector->>Wolf: Leaf証明書を解放
    Inspector->>TLS: デストラクター
    TLS->>Wolf: セッションとコンテキストを解放
    Inspector->>Wolf: wolfSSL_Cleanup()
    Inspector->>TCP: デストラクターでソケットをclose()
    Inspector-->>Main: Result（overall = PASS）

    Main->>Format: format_text(result) または format_json(result)
    Format-->>Main: 表示用文字列
    Main-->>User: stdoutへ結果を出力、終了コード0
```

The constructor's socket descriptor is borrowed by `TlsClient`; `TcpConnection` owns and closes the socket. The `wait_socket()` call is a free helper function, not a `TlsClient` member. DNS resolution occurs before initializing wolfSSL. Only combined verification and hostname success are reported as PASS; individual chain/date/trust success results are not invented. Limiting SAN text output does not limit certificate verification.

## Failed Inspection

This path shows an `inspector::Error` thrown during DNS resolution, TCP connection, TLS setup, the handshake, or a post-handshake check. A constructor that fails releases already-created resources; only successfully constructed objects are destroyed. Not all failures reach the TLS stage.

```mermaid
sequenceDiagram
    actor User as 利用者
    participant Main as main()
    participant Inspector as inspect()
    participant Stage as DNS / TCP / TLS / 接続後の確認
    participant Resources as RAIIで所有しているリソース
    participant Format as result_formatter.cpp

    Main->>Inspector: inspect(options)
    Inspector->>Stage: 接続・検証処理
    alt 証明書やホスト名の検証が失敗
        Stage->>Stage: wolfSSLの明示的なエラーコードを分類
        Note over Stage: 期限切れ・開始日前・名前不一致など<br/>不明な理由は推測で断定しない
    else DNSやTCP接続、TLS設定やプロトコルのエラー
        Stage->>Stage: 該当するエラー種別を設定
    else 待ち時間が期限を超過
        Stage->>Stage: TIMEOUTを設定
    end
    Stage-->>Inspector: Errorを送出
    Inspector->>Resources: スタック巻き戻しで作成済みリソースを解放
    Note over Resources: 該当する場合のみ、DNS子プロセス回収、証明書解放、<br/>TLSオブジェクト解放、wolfSSL_Cleanup()、ソケットclose()
    Inspector->>Inspector: catch(Error) でエラーをResultへ格納
    Note over Inspector: overall = FAIL<br/>明示的に分かった失敗だけ個別項目へ反映<br/>他の検証結果をPASSにしない
    Inspector-->>Main: Result（overall = FAIL）
    Main->>Format: format_text(result) または format_json(result)
    Format-->>Main: 表示用文字列
    Main-->>User: stdoutへ失敗結果、stderrへ診断を出力
    Main-->>User: エラー種別に対応する終了コードで終了
```

Argument errors are caught directly in `main()` and return exit code 2, with stderr diagnostics and a JSON failure report only when `--json` is present. `--help` returns exit code 0 without connecting. Other `std::exception` failures that escape inspection are caught by `main()` and return exit code 6; their JSON report is likewise emitted only in JSON mode.

Inspection failures return code 3 for classified certificate/hostname failures, 4 for DNS/TCP/TLS/configuration failures, 5 for timeouts, and 6 for other application failures. The failure report never treats an unsuccessful inspection as a successful TLS session.

## Viewing the Diagrams

Open this Markdown file in a Mermaid-compatible preview or in GitHub's rendered view after publishing. For [Mermaid Live Editor](https://mermaid.live/), copy one `sequenceDiagram` block at a time without the Markdown fences. Each block renders as a separate diagram. See the [class diagram](class-diagram.md#viewing-the-diagram) for additional viewing instructions.

These diagrams are maintained manually. Update them when changing the implementation's control flow or resource ownership.
