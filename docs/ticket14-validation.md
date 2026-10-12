# ローカル配布候補: 検証結果

検証日: 2026-10-11

## 実装した範囲

初期版を配布できるか判断するため、Linux amd64の単一バイナリ、SHA-256、build-info、問題報告とGitHub Releases向け手順を揃えた。2026-10-11の範囲縮小後、arm64成果物は配布対象から外し、コンパイル確認だけに使う。外部アップロード、push、公開設定変更は行っていない。

成果物は固定toolchain（Go 1.27.2、`golang.org/x/sys` v0.49.0、CGO無効、`-trimpath`）で再ビルドする。確認に使うのはイメージ内の`/opt/hwh`ではなく、その実行で作った`hwh-linux-amd64`である。

公開手順と残件は[ローカル配布候補](release-candidate.md)、報告先は[SECURITY.md](../SECURITY.md)を参照する。

## Q11の再確認

リリース候補作成前の一次資料確認では、Goの配布JSONの1.27系最新は1.27.2、公式module proxyの`golang.org/x/sys`最新はv0.49.0だった。版は更新していない。govulncheck v1.8.0は`No vulnerabilities found.`であり、未知の問題がない保証ではない。

## 配布物の起動と代表操作

Linux amd64、WSL2系6.18カーネル、Docker管理ボリューム上のext4で、ハッシュ済みamd64実行体をUID/GID 1000・capabilitiesなし・no-new-privileges・ネットワークなしで実行した。

| 項目 | 値 |
|---|---|
| CLI版 | `0.1.0-dev` |
| Go / x/sys / CGO | 1.27.2 / v0.49.0 / 0 |
| 直接依存 | `golang.org/x/sys` |

- `--version`: `hwh 0.1.0-dev`、終了0
- `check`: 終了0、`scan_status: not_started`、候補なし
- 書き込み可能経路の`check`: 終了3、`unsupported_mount`。拒否前後でmount optionと読み取り不能ファイルのmodeは不変
- quick: 終了2、候補パス2件
- deep: 終了2、候補パス3件
- 成果物に動的リンカがない
- 依存グラフに`net/http`と`crypto/tls`がない
- 合成canary本文の取り込みと、合成`AGENTS.md`命令の副作用なし

合成コピーの候補・除外・不完全状態の期待は[13のデモ](ticket13-validation.md)と同じ入力を使う。arm64成果物は配布物に含めない。成果物の具体ハッシュとソース照合の詳細は非公開の実行artifactへ残す。

## Q12 / Q13

著作権は留保し、利用許諾は与えない。一次資料は[LICENSE](../LICENSE)と[ローカル配布候補](release-candidate.md)である。SHA-256は破損検知、真正性は公式リポジトリ由来として区別し、GitHub Releases手順は文書化だけした。

通常不具合はGitHub Issues、脆弱性はSecurity Advisories（private中は所有者への非公開連絡）とした。自動更新はなく、支援契約でもない。

## 限界

この結果は、検証済みのLinux amd64/ext4合成環境でローカル成果物を起動できることを示す。arm64実機、XFS、Linux 5.10系は初期対応外である。コピー真正性、侵害判定、復旧、証拠保全は扱わない。
