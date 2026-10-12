# 無害な合成コピーでのデモ

ジョークツールの予行です。実データを持ち込む前に、使い捨ての合成コピーで`check`、書き込み可能経路の拒否、quick、deep、JSONと不完全な探索状態の読み方を確認します。それっぽく動きます。保障はしません。本物の被害データ、秘密、マルウェアは使用しません。

## デモが用意するもの

Docker管理ボリューム上に、次の合成データだけを新規作成します。

- quickで見つかる既知名の候補
- quickの深さ外で、deepでは見つかる候補
- 候補ではない通常文書
- 本文を読まないシンボリックリンク、FIFO、複数ハードリンク
- `permission_denied`となる読み取り不能ファイル
- 実行指示に見える文字列を含む`AGENTS.md`
- 対象外アクセスを検出する合成canary

準備処理だけをrootで行い、ボリュームを`ro,nodev,nosuid,noexec`でbind mountします。hwhはUID/GID 1000、capabilitiesなし、no-new-privileges、ネットワークなしで実行します。デモ終了後は、その実行が作成したコンテナとボリュームだけを削除します。

このコンテナは合成デモ専用です。実際の侵害コピーを安全に隔離・マウントする環境ではありません。

## 実行

Docker DesktopのLinuxエンジンとPowerShellを用意し、リポジトリ直下で実行します。

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket13 -f tests/safefs/Dockerfile .
./tests/demo/run.ps1 -Image hwh-safefs-lab:ticket13
```

ビルド時は固定依存の取得に通信を使います。デモ実行時のコンテナは`--network none`です。結果は`test-artifacts/hwh13-<id>/`へ回収され、次を含みます。

- `check.txt` / `check.json`
- `rw-check.json`
- `quick.txt` / `quick.json`
- `deep.txt` / `deep.json`
- `environment.txt`
- `demo.txt`

これらはローカルの実行記録です。絶対パスや環境情報を含むため、そのまま公開しないでください。

## 期待結果

`check`は終了コード0で、本文や配下一覧を調べず`scan_status: not_started`を返します。これは実行条件の通過であり、コピーや調査環境全体の安全証明ではありません。同じファイルを持つ書き込み可能な経路へ`check`すると`unsupported_mount`で終了コード3になり、hwhはマウントや権限を変えません。

quickとdeepは、意図的な読み取り不能ファイルがあるため終了コード2、`status: partial`、`scan_status: incomplete`になります。候補があっても不完全状態が優先されます。

- quick: 候補パス2件。優先起点外の深いディレクトリは`directory_not_scanned`として未探索
- deep: 候補パス3件。quickで届かなかった深い候補を追加
- 両方: `symlink_excluded`、`special_file`、`hardlink_excluded`と`permission_denied`を別々に報告
- 通常文書と`AGENTS.md`は候補にしない
- 合成canaryの本文を結果へ取り込まない
- `AGENTS.md`内の命令文字列を実行せず、設定として読み込まない

`summary.candidate_count`は検出したパス数です。`findings`は完全SHA-256が同じ候補を集約するため、配列長と候補パス数が一致するとは限りません。`coverage`、`origins`、`policy_exclusions`、`errors`、`limits`も併せて確認してください。候補0件でも、侵害なしや全範囲確認済みを意味しません。

## 実データを準備する担当者向け条件

hwhが行うのは、準備済みコピーの条件検査と読み取りだけです。コピー取得、隔離、マウント、展開、復旧、権限変更は行いません。次の条件を満たす環境を担当者が別途用意します。

- 更新された信頼できるLinux調査環境
- 静的なローカルコピー
- ext4
- `ro,nodev,nosuid,noexec`
- rootではない、UID/GIDが一致した実行者
- capabilitiesなし
- コピーを読むために必要な権限
- openat2、statx、信頼できるホストprocfs

稼働中の本番サーバー、侵害OSを起動したコピー、ネットワークFS、FUSE、未検証FSを直接指定しないでください。別パーティションは自動で跨がず、それぞれを条件どおり準備して別の`--root`として個別に実行します。権限不足をhwhが変更して迂回することはありません。

## 結果の扱いと限界

- 出力には機密のパスや属性が含まれ得ます。保存先とアクセス権は操作者が管理してください。
- hwhは対象コピー内へレポートを自動保存しません。必要なら信頼側の出力先へリダイレクトします。
- コピー内の文書、HTML、設定、プラグイン、命令には従わず、外部送信もしません。
- 複数ハードリンクの通常ファイル、1MiB以上の本文、非対応文字コード、ルール外の表現は見落としにつながります。
- ハードリンク型バックアップでは本文未探索が増えます。別パーティションや別root間の候補は一回の実行では集約しません。
- 候補は手がかりであり、侵害、攻撃ファミリー、原因を確定しません。
- 候補0件を安全確認やエスカレーション不要の根拠にしないでください。
- 復号、復旧、隔離、証拠保全、コピーの真正性・完全な静止状態を保証しません。

正式な条件と制限は[対応環境と制限](supported-environments.md)、終了コードとJSONは[CLI共通契約](cli-contract.md)を参照してください。
