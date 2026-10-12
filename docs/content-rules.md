# 内容ルール

06の実装前に定めた期待値と初期ルール。合成例での評価であり実環境の精度保証ではない。

探索範囲内の通常ファイルは名前・拡張子によらず既存の固定FD経路で本文取得を試みる。1MiB未満、単一リンク、UTF-8（ASCII/BOMを含む）の条件、起点8MiB・全体64MiBの実読取予算を維持する。非対応文字コード・バイナリは内容判定しない。大きい通常文書でも予算を消費するため見落としはあり得る。

Go正規表現の大小文字無視とASCII単語境界を使い、境界付きの固定フレーズを照合する。英語以外の翻訳、HTMLのタグ除去、実行、文字実体展開はしない。空白はTAB/CR/LFを含め連続を許す。

| 特徴 | フレーズ |
|---|---|
| A 暗号化の主張 | your files are encrypted / your files have been encrypted / we encrypted your files / all your files are encrypted |
| R 復旧案内 | decrypt your files / recover your files / restore your files / decryption key / decryption tool |
| P 支払い要求 | pay bitcoin / pay in bitcoin / send bitcoin / pay the ransom / ransom payment |
| C 連絡要求 | contact us / email us / write to us / contact our team |

`content.encryption-recovery-payment`はA+R+P、`content.encryption-recovery-contact`はA+R+C。両方成立なら両IDと理由を出す。確からしさは`content_pattern`（文面の複合特徴）または`name_pattern`（名前一致）だけとし、確率・深刻度・侵害/ファミリーの確定を示さない。各フレーズは本文全体で照合するため、引用された要求文や無関係な段落間の組み合わせでも誤検出し得る。

JSONの`detection_basis`で上記を区別。`content_status=complete`は取得成功だけを表し、内容一致とは別。`scope.content_scanned=true`は判定機能を有効にして探索を開始した意味で、全ファイルを確認した意味ではない。本文・連絡先の抜粋は既存契約どおり出さず`excerpt=null`。理由は固定文のみ。

## 実装前の合成コーパス期待値

| 例 | 意味上の正解 | 期待する一致 |
|---|---|---|
| 平凡な名前のA+R+P要求文 | 要求文 | payment |
| 拡張子なしのA+R+C要求文 | 要求文 | contact |
| 大文字/BOM/改行を含むA+R+P+C | 要求文 | 両方 |
| HTML原文内の連続したA+R+C | 要求文 | contact |
| AGENTS.md内の実行指示とA+R+C | 要求文 | contact、実行なし |
| 双方向制御文字とA+R+C | 要求文 | contact、本文非表示 |
| 通常README、暗号化技術説明、bitcoin単語、連絡情報だけ、A+Rだけ、単語の部分一致 | 通常文書 | なし |
| 教育文書でA+R+Pを引用 | 通常文書 | payment（既知の誤検出） |
| 別表現の要求文、日本語要求文、タグでフレーズを分断 | 要求文 | なし（既知の見落とし） |
| UTF-16、不正UTF-8、NUL/ESC入り要求文 | 要求文 | 判定対象外（既知の見落とし） |

コーパスのバイト列とルール別期待値は`tests/scan/content_cases.json`に保持する。11で測定前基準を定め、20例の期待一致、precision 85.7%、recall 46.2%を確認した。小さい限界集合の結果であり、実環境精度ではない。[評価方法](evaluation-method.md)と[結果](ticket11-validation.md)を参照。
