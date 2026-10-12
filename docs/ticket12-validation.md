# 対応環境横断検証

検証日: 2026-10-11。利用可能なLinux amd64／ext4環境で必須36ケースの再実行と3境界のfuzzを完了した。同日、所有者の承認により初期対応をこの検証済み範囲へ縮小した。arm64実機、XFS、5.10系は未実施のまま対象外とする。クロスビルドやエミュレーションで代替しない。

## 実行環境と範囲

| CPU | カーネル系統 | FS | 結果 |
|---|---|---|---|
| amd64 | WSL2系6.18 | ext4、ro/nodev/nosuid/noexec | 初期対応。E01–E10、F01–F12、R01–R08、O01–O06とfuzzが合格 |
| arm64 | 任意 | 任意 | 初期対応外。実行時は`unsupported_environment` |
| amd64 / arm64 | 任意 | XFS | 初期対応外。実行時は`unsupported_mount` |
| 任意 | 5.10系など未検証系統 | 任意 | 初期対応外。必須APIが使えなければ拒否 |

Go 1.27.2、`golang.org/x/sys` v0.49.0、CGO無効の同じソースから試験バイナリとCLIを作成した。試験時のネットワークを無効にし、合成fixtureの準備だけを権限付きプロセスで行った。製品CLI、probe、fuzz対象はUID/GID 1000、capabilitiesなし、no-new-privilegesで実行した。実データは使用していない。

## 必須36ケース

既存の公開CLI試験、`internal/safefs`の故障注入、独立syscall監査を一つの回帰として再実行し、E01–E10、F01–F12、R01–R08、O01–O06がすべて合格した。個別条件と合格基準は[受け入れ試験仕様](security-acceptance-tests.md)、各機能の詳細な導入時結果はチケット01–11の検証記録を参照する。

| ID | 今回の証跡 | 結果 |
|---|---|---|
| E01 | `tests/check/check_cli.py`: 未指定・相対・`..`・`/`・不存在 | 合格 |
| E02 | `tests/check/check_cli.py`: root・途中リンク | 合格 |
| E03 | `tests/check/privileges.py`: root、UID/GID不一致、capability、bounding-only対照 | 合格 |
| E04 | `tests/check/check_cli.py`: openat2/statx故障・mask欠落 | 合格 |
| E05 | `tests/check/check_cli.py`: procfs偽装・欠落・読取不能 | 合格 |
| E06 | `tests/check/check_cli.py`: rw、nodev/nosuid/noexec欠落、再検査 | 合格 |
| E07 | `tests/check/check_cli.py`: tmpfs・overlay。XFSは`TestMountinfoRejectsXFS` | 合格 |
| E08 | `tests/check/check_cli.py`: 準備済みext4コピー | 合格 |
| E09 | `tests/check/check_cli.py`: mountinfo ID・dev・行数・バイト数・構文 | 合格 |
| E10 | `tests/scan/environment.py`: check後の条件変化 | 合格 |
| F01 | `TestF01RejectOutsidePaths`、`TestF01ReadPinnedRegularFile`、scan監査 | 合格 |
| F02 | `TestF02LinksArePolicyExcluded`、独立probe | 合格 |
| F03 | `TestF03MountBoundaries`、quick/deep監査 | 合格 |
| F04 | `TestF04SpecialFilesNeverReopened`、独立probe | 合格 |
| F05 | `TestF05HardlinksAndDirectory`、独立probe | 合格 |
| F06 | `TestF06PermissionNotBypassed`、本文CLI試験 | 合格 |
| F07 | `TestF07PathReplacementDoesNotRedirectRead` | 合格 |
| F08 | `TestF08ReopenFailureHasNoFallback` | 合格 |
| F09 | `TestF09DescriptorLifetime`、停止・出力切断試験 | 合格 |
| F10 | `TestF10ReopenedIdentityMismatchReadsNothing` | 合格 |
| F11 | `TestF11PinnedDirectoryMoved`、quick移動試験 | 合格 |
| F12 | `TestF12BoundedEAGAIN` | 合格 |
| R01 | `TestBoundedReadsAndCompleteHashes`、`tests/scan/body_cli.py` | 合格 |
| R02 | 本文総量、quick起点/全体、deep総量の各予算試験 | 合格 |
| R03 | `tests/scan/scan_cli.py`の有限列挙・RSS観測 | 合格 |
| R04 | deep深さ/パス/キュー、候補・エラー・出力保持試験 | 合格 |
| R05 | 本文故障注入と`TestBodyScanStopsAndClosesOnFailure` | 合格 |
| R06 | quick公平性・FD、deep待ち行列試験 | 合格 |
| R07 | SIGINT/SIGTERM、期限、出力切断試験 | 合格 |
| R08 | `tests/scan/dedup_cli.py`: 同一内容、hashなし、保持上限 | 合格 |
| O01 | check/scan/contentの制御文字・不正UTF-8・双方向制御試験 | 合格 |
| O02 | check/scanのJSON・255/256/257/4095/4096境界 | 合格 |
| O03 | 最大エスケープ時の出力予約・JSON終端試験 | 合格 |
| O04 | 0候補と除外・権限・上限のcoverage分離試験 | 合格 |
| O05 | `tests/scan/joke_cli.py`: 全状態・JSON・quiet不変 | 合格 |
| O06 | `tests/scan/content_cli.py`とscan監査: 指示をデータ扱い | 合格 |

独立probeは正常例を正の対照として本文open 1回・read 2回を観測した。対象外パス、リンク、別マウント、FIFO、socket、デバイス、複数ハードリンク、権限不足の16例では、成功・失敗を問わず禁止した本文open試行と対象readを監査し、いずれも0だった。監査器が失敗した禁止open/readも検出することは4つの負の対照で確認した。scan側でも範囲外canary、特殊ファイル、別マウントを含む監査が合格した。検出0件やatimeだけを禁止アクセスなしの根拠にはしていない。

## 固定案内ファイルの本文探索

quickの固定案内ファイル`etc/motd`、`tmp/motd`、`tmp/index.html`も、列挙で見つけた通常ファイルと同じpin、本文FD再取得、型・リンク・サイズ、起点8MiB／全体64MiB予算、事後検査で読む。本文の権限不足・起点予算・全体停止理由も起点状態へ反映する。合成`etc/motd`の名前を検出理由にせず、本文の複合条件だけで候補とする。全36ケースと禁止アクセス監査が合格した。

## fuzz

`go test -fuzz`を各対象30秒、2 worker、2 CPU・512MiB上限で実行した。

| 対象 | 検査する性質 | 実行数 | 結果 |
|---|---|---:|---|
| 相対パス検証 | 空、絶対、NUL、`.`/`..`、空成分、4096バイト境界を受理しない | 1,704,753 | 縮小後に30秒再実行し合格 |
| mountinfo解析 | 任意バイト列でpanicせず、成功時は整合するext4だけ、失敗は安定した環境/マウント分類 | 1,561,298 | 縮小後の受理条件で再実行し合格 |
| 安全なパス表示 | Base64が元バイトへ可逆、表示が印字可能ASCII、切り詰め境界とJSONが有効 | 156,030 | 縮小後に30秒再実行し合格 |

シードには改行、ESC、双方向制御文字、不正UTF-8、引用符、壊れたmountinfo、保護不足マウントを含めた。失敗・panic・再現コーパスの生成はなかった。再現方法は[開発版の使い方](usage.md)を参照する。

## 結論

初期対応はLinux amd64／WSL2系6.18系統／ext4に限定する。縮小前の同日36ケースと禁止アクセス監査は、この環境のext4経路に対して合格している。縮小後はcheck回帰、XFS拒否単体、3境界fuzz、amd64配布ハーネスを再実行した。arm64実行とXFSは検査で拒否し、未検証カーネル系統を対応済みと表示しない。V02は縮小後の掲げている環境について完了とする。
