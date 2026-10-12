# 安全な単一ファイル読み取り: 検証結果（公開用要約）

検証日: 2026-10-10。非配布の最小試作。製品CLI、探索、検出、JSON契約は未実装。環境条件と結果を要約し、個人パス、実行ID、ローカル生成物の識別子、障害対応記録、生ログは含めない。

## 実装と境界

`internal/safefs` が明示した絶対ルートを固定し、制約付きopenat2 → O_PATHの型・nlink確認 → 自身の固定procfs FDから保持中FDを再取得 → 同一性・属性・マウント再照合 → 上限付きreadを行う。対象の元パスを本文用に開き直さない。RootがFDを所有し、Read/Closeを直列化する。root権限、UID/GIDの不一致、有効・許可・継承・ambient capabilitiesを拒否する。

本文は通常ファイルnlink=1だけ。リンク、別マウント、特殊ファイルは本文用open前に除外する。32KiB単位、最大1MiBまで読み、EOFと事後検査が成立した場合だけ内容と完全SHA-256を返す。失敗時は内容もハッシュも返さない。対象の書換え・実行・外部通信はしない。

試験準備だけがDocker内の権限を持つ。新規のDocker管理ボリュームに無害な文字列・リンク・FIFO等を作り、ro/nodev/nosuid/noexecのbind mountを作成する。試験とprobeはUID/GID1000、capabilitiesなし、no-new-privilegesで実行。実行時ネットワークはnone、ホストの対象データ・Docker socket・PID namespaceは共有しない。準備用SYS_ADMIN等を与えたこのコンテナは**合成データ専用**であり、実際の侵害コピーを扱う隔離環境として提示しない。

競合試験だけは準備側のrw aliasで合成ファイルを差し替える。非公開のsafefs/OS境界で再取得・属性・read等を注入し、製品に保護解除オプションを追加しない。実データ向けの準備手順、完全な環境検査、探索との統合、対応環境横断検証は後続の実装で行う。

## 再現手順

プロジェクト直下でDocker DesktopのLinuxエンジンを起動済みとし、PowerShellから実行する。

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket01 -f tests/safefs/Dockerfile .
./tests/safefs/run.ps1
```

`-TestPattern TestF02`等で絞れる。各実行は一意なコンテナ・ボリュームを作成し、結果を`test-artifacts/hwh01-<id>/`へ回収後、その実行が作成した資源だけを削除する。中断などで残った資源はhwh.safefs.lab=ticket01ラベルと一意名を確認して扱う。既存ボリュームを流用しない。

イメージ構築時は依存取得の通信を使う。試験実行は無通信。`.dockerignore`は必要なソースだけを許可する。`.gitignore`はtest-artifacts、bin等を除外する。生のtraceをコミットしない。合成データでもホスト固有の識別子を含むためである。

## 固定依存と更新確認

| 対象 | 固定値 | 根拠 |
|---|---|---|
| Go | 1.27.2、CGO_ENABLED=0 | 実装日の安定版。2026-10-08の修正版を一次資料で確認し、固定したtoolchainでビルド |
| golang.org/x/sys | v0.49.0 | openat2/statx等のLinux APIに必要。公式module proxyの版・公開日2026-10-06を確認、go.sumに固定 |
| Dockerベース | golang:1.27.2-bookworm（digest固定。具体値はDockerfile） | 再現用にdigestへ固定 |
| 脆弱性検査 | golang.org/x/vuln/cmd/govulncheck v1.8.0 | 公式module proxyで版を確認。開発時の検査専用依存 |

一次資料: [Go修正リリース](https://go.dev/doc/devel/release)、[Go配布情報](https://go.dev/dl/?mode=json)、[x/sysの公式API](https://pkg.go.dev/golang.org/x/sys/unix)、[公式module proxy](https://proxy.golang.org/golang.org/x/sys/@v/v0.49.0.info)、[govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)。

試験ツールはDebianのstrace 6.1-0.1、Python 3.11.2-1+b1、util-linux 2.38.1-5+deb12u3。aptのリポジトリはsnapshot固定していないため、将来の試験用パッケージは更新され得る。実行環境記録とベースdigestで検証条件を区別する。配布物にこれらを含めない。

更新確認: 依存変更時とリリース候補作成前に上記一次資料とGo vulnerability DBを確認し、govulncheckを実行する。新しい修正は版・digest・go.sumをレビューして更新し、F01–F12と禁止アクセス観測を再実行する。自動的な最新版への追従や安全性の保証はしない。

```sh
go vet ./...
GOARCH=arm64 go build ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

これらをビルド用コンテナ内で実施済み。vetとarm64クロスビルドは成功、govulncheckは`No vulnerabilities found.`。これは2026-10-10時点の検査結果であり、未知の問題がないという保証ではない。

## 検証環境と予定表

| CPU | カーネル | FS | 状態・担当 |
|---|---|---|---|
| amd64 | WSL2系6.18 | ext4 | 試作でDocker実行済み。F01–F12、probe監査が合格。2026-10-11以降の初期対応 |
| arm64 | 同上相当または対応LTS | ext4 | 当時は予定。初期対応外へ変更。実行時拒否 |
| amd64 / arm64 | 対応LTS | XFS | 当時は予定。初期対応外へ変更。実行時拒否 |
| amd64 / arm64 | 5.10の保守更新版 | ext4 / XFS | 当時はAPI下限の予定。初期対応外へ変更 |

Linuxコンテナで実行した。Dockerのローカル環境識別情報は公開要約から除いている。対象はDocker管理ボリューム上のext4であり、Windowsドライブのファイル共有ではない。findmntでro,nosuid,nodev,noexecを確認。この結果は上記1環境での方式の初期実証に限る。現行の掲げている範囲は[対応環境](supported-environments.md)を参照。

## 試験結果と観測方法

| 試験 | 結果・観測 |
|---|---|
| F01 | 内側のabcだけが読め、既知SHA-256と一致。絶対・相対の外側指定を拒否 |
| F02 | 外部・内部・相対・途中リンクを除外。末尾O_PATH成功後も型で除外 |
| F03 | 別FSのtmpfs、同じdevのbind mountをNO_XDEVで遮断 |
| F04 | FIFO/socket/char/blockをO_PATHまでに限定。本文再取得に入らない境界アサーション＋独立trace |
| F05 | 内部・内外ハードリンクを除外。nlink0は境界で注入。rootディレクトリnlink>1を受容 |
| F06 | mode000の通常ファイルでpermission_denied。権限を迂回しない |
| F07 | pin後にリンク/FIFO/別ファイルへ差し替え。停止または元の保持実体のみ。観測したreadに置換後の文字列がない |
| F08 | proc再取得をEIOで失敗させ、再取得1回・read0。元パスfallbackなし |
| F09 | 成功/キャンセル/エラー/panicを各20回。pinの生存、終了後EBADF、FD数の不増加、Close再実行時の別FD保護を確認 |
| F10 | 本文FDの型/dev/inode/mount IDを不一致にし、本文read0で停止 |
| F11 | 固定済みディレクトリを外へ移動し、属性変化を検出して停止。現在位置の完全保証は主張しない |
| F12 | EAGAIN継続時、同じflags/resolveで計3回（再試行2回）だけ実行して停止 |

テストバイナリのsyscall traceとは別に、fixture変更をしない独立probeを17ケースで起動し、open系/read系をstraceで監査する。正常例は本文open1回・read2回以上を要求する正の対照。禁止対象は成功した本文open/readが0であり、失敗した禁止open試行も監査で拒否する。権限不足ファイルへの失敗openは許容。監査自体には、失敗したFIFO/外側/デバイスのopenとsocket readを模した負の対照を含める。


## 残る制限

- ちょうど1MiBの場合、追加のreadでEOFを確認する予算がないためErrLimitとして内容・ハッシュを返さない。上限超過ファイルは本文read0。1MiB未満を読み切った場合のみ完全ハッシュを出す。製品の境界値契約で1MiBを含む上限をどう扱うか正式に決め、追加1バイトを無断で予算外読取しない。
- 静的なコピーの準備は信頼側の責任。メタデータ比較で観測できない変更、悪意あるカーネル/FS、ホスト侵害、全体の時点一貫性は保証しない。
- この試作は環境条件の一部を拒否するが、製品の全preflight検証、ディレクトリ列挙予算、全体I/O/時間制限、製品終了コードを実装したものではない。
- Goのcontext確認は同期readを強制中断しない。ローカルFSを前提とし、製品の停止・時間予算の統合は後続で検証する。


04で境界値契約を[本文契約](body-read-contract.md)として確定した。現在は1MiB以上を本文open前に除外する。本書の結果は01時点の試作記録である。
