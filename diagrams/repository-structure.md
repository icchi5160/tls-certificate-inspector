<!-- SPDX-License-Identifier: GPL-3.0-only -->

# リポジトリのファイル構造

TLS Certificate Inspectorのソース、設定、テスト、設計資料の配置を説明します。以下はGitで管理するファイルの構成です。ビルド成果物や導入した依存ライブラリは、後半で別に説明します。

```text
tls-certificate-inspector/
├── .clang-format
├── .gitignore
├── CMakeLists.txt
├── LICENSE
├── README.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── include/
│   ├── certificate_info.hpp
│   ├── certificate_inspector.hpp
│   ├── result_formatter.hpp
│   ├── tcp_connection.hpp
│   └── tls_client.hpp
├── src/
│   ├── main.cpp
│   ├── certificate_info.cpp
│   ├── certificate_inspector.cpp
│   ├── result_formatter.cpp
│   ├── tcp_connection.cpp
│   └── tls_client.cpp
├── tests/
│   ├── CMakeLists.txt
│   ├── test_cli.cpp
│   ├── test_certificate.cpp
│   ├── integration.py
│   └── fixtures/
│       └── generate.py
├── scripts/
│   └── install-wolfssl.sh
└── diagrams/
    ├── repository-structure.md
    ├── class-diagram.md
    ├── sequence-diagram.md
    ├── class_diagram.svg
    ├── s1_diagram.svg
    └── s2_diagram.svg
```

## 各フォルダーの役割

| フォルダー | 役割 |
| --- | --- |
| `include/` | ほかのソースから利用する関数の宣言、クラス・構造体などの定義を置く |
| `src/` | CLI、TCP接続、TLS接続、証明書解析、出力の実装を置く |
| `tests/` | C++の単体テスト、PythonのローカルTLS統合テストと、そのCMake設定を置く |
| `tests/fixtures/` | テスト用のCA・サーバー証明書・秘密鍵を生成するスクリプトを置く |
| `scripts/` | 開発環境や依存ライブラリを準備する補助スクリプトを置く |
| `diagrams/` | ファイル構造の説明、Mermaidの設計図と、そのSVG出力を置く |
| `.github/workflows/` | GitHub Actionsによる自動チェックの設定を置く |

## ルートの設定・説明ファイル

| ファイル | 役割 |
| --- | --- |
| [`README.md`](../README.md) | 概要、要件、ビルド・実行方法、検証方針、テスト、制約、ライセンスを説明する |
| [`CMakeLists.txt`](../CMakeLists.txt) | C++17、wolfSSLの検出・バージョンと機能の検査、ビルド対象、テスト、Sanitizer、インストールを設定する |
| [`.clang-format`](../.clang-format) | C++コードのインデント、改行、行幅などを統一する |
| [`.gitignore`](../.gitignore) | ビルド成果物、依存ライブラリ、生成した秘密鍵などをGitの管理対象から除外する |
| [`LICENSE`](../LICENSE) | 自作部分に適用するGPLv3の全文を置く。第三者ライブラリには、そのライブラリ自身の条件が適用される |

## ソースとヘッダーの対応

| 実装 | 対応するヘッダー | 主な内容 |
| --- | --- | --- |
| [`src/main.cpp`](../src/main.cpp) | なし | プログラムの入口。引数解析・検査・整形を呼び出し、標準出力・標準エラーと終了コードを扱う |
| [`src/tcp_connection.cpp`](../src/tcp_connection.cpp) | [`include/tcp_connection.hpp`](../include/tcp_connection.hpp) | `TcpConnection`。期限付きの名前解決・非ブロッキングTCP接続、ソケットの所有と解放、待機用の補助関数 |
| [`src/tls_client.cpp`](../src/tls_client.cpp) | [`include/tls_client.hpp`](../include/tls_client.hpp) | `TlsClient`。wolfSSLのコンテキスト・セッション管理、CA・SNI・ホスト名検証の設定、ハンドシェイク、TLSエラーの分類 |
| [`src/certificate_info.cpp`](../src/certificate_info.cpp) | [`include/certificate_info.hpp`](../include/certificate_info.hpp) | 証明書情報の取得、エラー種別の表示名・終了コード。ヘッダーには`Options`、`CertificateInfo`、`Result`、`Error`なども定義する |
| [`src/certificate_inspector.cpp`](../src/certificate_inspector.cpp) | [`include/certificate_inspector.hpp`](../include/certificate_inspector.hpp) | `parse_arguments()`と`inspect()`。CLIの入力を確認し、接続・検証・証明書解析を統合して結果を返す |
| [`src/result_formatter.cpp`](../src/result_formatter.cpp) | [`include/result_formatter.hpp`](../include/result_formatter.hpp) | `format_text()`、`format_json()`、`usage()`。結果とヘルプの表示用文字列を作る |

ヘッダーには宣言だけでなく、構造体・クラスの定義や短いメンバー関数の実装も含まれます。すべてのファイルがクラスを定義するわけではなく、処理の統合・証明書解析・出力整形は主に通常の関数として実装しています。`.cpp`ごとに`.hpp`が必須というC++の規則はありません。

## テスト・補助スクリプト

| ファイル | 役割 |
| --- | --- |
| [`tests/CMakeLists.txt`](../tests/CMakeLists.txt) | テスト用実行ファイルの作成、Python依存の確認、CTestへの登録を行う |
| [`tests/test_cli.cpp`](../tests/test_cli.cpp) | 引数解析、終了コード、名前解決のタイムアウトと子プロセス回収を確認する |
| [`tests/test_certificate.cpp`](../tests/test_certificate.cpp) | TLSエラーの分類、情報がない場合の扱い、テキスト・JSON整形、SANの表示制限を確認する |
| [`tests/integration.py`](../tests/integration.py) | ローカルTLSサーバーを起動し、正常な証明書・不正な証明書・接続エラー・タイムアウトなどを実際のCLIで確認する |
| [`tests/fixtures/generate.py`](../tests/fixtures/generate.py) | テスト専用のCA、証明書、秘密鍵を再生成する。統合テストは一時ディレクトリで利用し、終了後に削除する |
| [`scripts/install-wolfssl.sh`](../scripts/install-wolfssl.sh) | wolfSSL 5.9.4のソースを取得し、固定したSHA-256で照合してから、必要な機能を有効にして指定先へビルド・インストールする |
| [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) | push・pull request時に整形チェックと、固定したwolfSSLを使う通常・Sanitizerビルド／テストを実行する |

## 設計資料

| ファイル | 内容 |
| --- | --- |
| [`class-diagram.md`](class-diagram.md) | 主要なクラス・構造体・関数群と、その依存・所有関係 |
| [`sequence-diagram.md`](sequence-diagram.md) | 正常系と異常系の処理順序、接続・検証・リソース解放の流れ |
| [`class_diagram.svg`](class_diagram.svg) | クラス図のSVG画像 |
| [`s1_diagram.svg`](s1_diagram.svg) | 正常系シーケンス図のSVG画像 |
| [`s2_diagram.svg`](s2_diagram.svg) | 異常系シーケンス図のSVG画像 |
| `repository-structure.md` | このファイル。リポジトリの配置と各ファイルの役割 |

Mermaidの図はMarkdown内のコードブロックに記述されています。SVGは書き出した時点の画像であり、MarkdownやC++コードの変更に自動追従しません。構造や処理を変更した場合は、図のソースを更新し、必要に応じてSVGを再生成します。

## ローカルに生成されるフォルダー

以下は作業環境に存在することがありますが、通常のGit管理対象には含めません。

```text
tls-certificate-inspector/
├── .git/                         Gitの内部管理情報
├── .deps/
│   └── wolfssl-5.9.4/
│       ├── include/wolfssl/       導入したwolfSSLのヘッダー
│       ├── lib/                  wolfSSL共有ライブラリと関連設定
│       └── share/doc/wolfssl/    wolfSSLのCOPYING・LICENSING
├── build/                        通常のビルド結果
├── build-sanitize/               ASan／UBSanを有効にしたビルド結果
├── build-*/                      更新確認などに使った補助ビルド
└── tests/fixtures/generated/     手動で生成したテスト用証明書・秘密鍵
```

| 場所 | 作るもの・用途 |
| --- | --- |
| `build/tls-inspector` | ツール本体の実行バイナリ |
| `build/libinspector_core.a` | 標準設定で生成される、自作の共通処理をまとめた静的ライブラリ。本体とC++テストのリンクに使用する |
| `build/tests/test_cli`・`test_certificate` | テスト用の実行バイナリ |
| `build/CMakeFiles/` | コンパイルした`.o`などの中間生成物と、ビルドの内部管理情報 |
| `build/CMakeCache.txt`・`Makefile`など | CMakeが記録する設定や生成するビルド手順。`Makefile`の有無は選択したビルド方式による |
| `build/Testing/` | CTestの結果・ログ |
| `.deps/` | 導入スクリプトで指定した場合の、外部依存の配置先。wolfSSL本体のソースをリポジトリへ取り込むものではない |
| `.git/` | コミット・ブランチ・リポジトリ固有の設定などを保存する。`build/`とは異なり、ソースから再生成できるビルド成果物ではない |

`build-sanitize/`内も同様の構成ですが、アプリケーションとC++テストにSanitizerの検査機能が入ります。`__pycache__/`や`.pyc`もPythonによる生成物として除外しています。テスト用でも秘密鍵を公開対象に含めないでください。

## 読む順番の例

1. [`README.md`](../README.md)で全体像と動かし方を確認する。
2. [`src/main.cpp`](../src/main.cpp)でプログラムの入口を見る。
3. [`src/certificate_inspector.cpp`](../src/certificate_inspector.cpp)で全体の処理順序を追う。
4. `include/`と対応する`src/`を読み、各処理の責務・実装を確認する。
5. `tests/`で正常系・異常系の期待結果を確認する。
6. 必要に応じて`CMakeLists.txt`、導入スクリプト、CI設定を確認する。

この説明は手動で管理しています。ファイルの追加・移動や責務の変更時には、構成図と説明も更新してください。
