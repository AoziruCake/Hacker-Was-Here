# メッセージ配置場所の調査

調査日: 2026-10-09

## 結論と根拠の扱い

公開された一次分析には、暗号化対象ディレクトリ、ファイルシステムのルート、ログイン時の案内、管理画面に要求文を置く事例がある。

今回確認した資料は個別ファミリー・検体の分析であり、Linux全体の配置頻度ランキングではない。「報告で確認された配置」「暗号化対象から推測する探索先」「一般的な運用上の候補」を分ける。過去の事例から現在の検出率は算出しない。

## 公開資料で確認できる例

### R1: BlackSuit — 対象フォルダ

SentinelOneの分析は、Linux版が対象フォルダに `README.blacksuit.txt` を配置すると記載している。固定されたシステムディレクトリだけでなく、利用者のデータ保存先を探す根拠となる。

出典: [BlackSuit Ransomware: Analysis, Detection, and Mitigation](https://www.sentinelone.com/anthology/blacksuit/)

### R2: Play ESXi版 — ルートとデータストア領域

CISA等の共同アドバイザリの2025-06-04更新では、ESXi版がルートディレクトリと `/vmfs/volumes/` に `PLAY_Readme.txt` を作成し、ESXiのウェルカムメッセージにも要求文を設定すると記載している。

ここでいうルートディレクトリは `/` であり、管理者のホーム `/root` とは区別する。これはESXiの事例で、一般Linuxの配置頻度を示すものではない。

出典: [#StopRansomware: Play Ransomware — AA23-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a)

### R3: ESXiArgs — ログイン案内と管理画面

Trend Microの検体分析は `/etc/motd` と `/usr/lib/vmware/index.html` を要求文の配置先としている。準備用の構成ファイルとして `/tmp/motd` と `/tmp/index.html` も記載されている。

一時配置のファイルは攻撃後に残るとは限らない。`motd` は拡張子を持たず、`index.html` は一般的な名称なので、ファイル名だけでは判定できない。

出典: [Ransom.SH.ESXIARGS.THBOFBC — Trend Micro](https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/ransom.sh.esxiargs.thbofbc)

### R4: Dark Angels — 暗号化ファイルごとの要求文

SentinelOneの2024-01-18更新の分析は、調査したESXi向け検体で、暗号化した各ファイルに対応する `<encrypted_file_name>.crypted.README_TO_RESTORE` が作成されたと報告している。

固定ファイル名や `.txt` のみを探すと見落とす。接尾辞パターンと拡張子に依存しない候補選択が必要。

出典: [Dark Angels — ESXi Ransomware Borrows Code & Victimology From RagnarLocker](https://www.sentinelone.com/blog/dark-angels-esxi-ransomware-borrows-code-victimology-from-ragnarlocker/)

### R5: Linux.Encoder.1 — 探索先を考える補助資料

Bitdefenderの2015-11-09の分析は `/home`、`/root`、`/var/lib/mysql` を初期の暗号化対象として説明している。これは古い事例であり、この資料だけで各パスへの要求文配置を断定しない。

データ保存先と要求文探索を結びつける補助的根拠として用いる。データベース本体を解析する計画ではない。

出典: [Linux Ransomware Debut Fails on Predictable Encryption Key](https://www.bitdefender.com/en-us/blog/labs/linux-ransomware-debut-fails-on-predictable-encryption-key)

## hwhへの反映案

以下は資料を踏まえた設計判断であり、統計的な頻度順ではない。パスはコピー内の位置として扱い、ホスト側の同名パスを探索しない。現在の利用条件は [安全なアクセス設計](safe-file-access-design.md) に従う。

| 優先段階 | 探索対象 | 根拠・扱い |
|---|---|---|
| 1 | `/` 直下の通常ファイル、`/etc/motd`、`/tmp/motd`、`/tmp/index.html` | R2/R3の配置事例を参考に、低コストの直接確認。Linuxへの適用は設計上の推論 |
| 2 | `/root`、`/home`内の各ホーム、`/srv`、`/var/www`、`/var/lib/mysql` | R1の対象フォルダ配置とR5の暗号化対象、サーバーでの利用場所を組み合わせた推論 |
| 3 | `/tmp`、`/var/tmp`、存在する `/data`、`/backup`、`/backups`、`/opt` | 補助候補。特に後者のパスについて、今回の資料で頻出配置は未確認 |
| 別途指定 | 業務データやバックアップの独自パス、別パーティションのコピー | 対応条件を満たすローカルコピーを別の--rootとして別実行。ネットワーク共有の直接探索は初期対応外 |
| 将来拡張 | ESXiのデータストアと管理画面 | R2/R3に直接根拠。ただしLinux版の実行対応とは分離 |

`/etc/issue`、`/etc/issue.net` もログイン案内の追加候補だが、今回の資料では要求文の配置実績を確認していない。採用する場合は推測候補として記録する。

## 探索方法への影響

1. ユーザー指定パスがある場合はその範囲を守り、ホスト側の `/etc/motd` 等を勝手に追加しない。
2. quickでは固定ファイルを先に確認。その後、各起点を浅く広く交互に探索する。一つの巨大ディレクトリに時間を使い切らない。
3. `/home` の直下だけでは不十分。各ホームの直下も優先する。
4. `.txt`、`.html`だけでなく、既知の名前・接尾辞・固定ファイルと、小さな拡張子なしのテキスト候補も扱う。
5. 通常のREADMEや管理画面を存在だけで検出しない。場所は探索順の根拠であり、悪性の根拠ではない。
6. 指定root配下の別マウントを跨がず、自動で別の起点として追加しない。必要なら対応条件を満たすローカルコピーを別指定する。ネットワーク先は明示指定でも初期対応外。root自体の到達経路は担当者が自動マウント等を使わず準備する。
7. 重複集約は完全な内容ハッシュで行う。文面にファイル名や個別IDを含む要求文は同一ハッシュにならない場合がある。
8. 全体の処理量と起点ごとの処理量を制限し、未探索・途中終了・除外の理由を記録する。

## 限界

- 事例のある場所を優先しても、独自パスや新しいファミリーを網羅できない。
- 要求文が既に削除・暗号化されている場合もある。
- ESXiはLinux向けGoバイナリがそのまま動く前提にしない。将来の対応では実行環境または取得済みファイルの調査方法を別途検証する。
- 保全コピーを調べるときのパス解釈と、稼働中ホストのパス解釈を混同しない。
