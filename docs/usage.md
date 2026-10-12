# 開発版の使い方

ジョークツールです。起動条件を見る`hwh check`、優先起点で名前・内容の候補を拾う`hwh scan`、単一ファイル読み取りを試験するprobeがあります。それっぽく動きます。保障はしません。実データへ持ち込む前の[無害な合成デモ](safe-demo.md)も用意しています。合成データで遊んでください。

## 最初に実行する合成デモ

使い捨てコピーでcheck、書き込み可能経路の拒否、quick、deep、JSON、除外と不完全状態を順に確認します。

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket13 -f tests/safefs/Dockerfile .
./tests/demo/run.ps1 -Image hwh-safefs-lab:ticket13
```

デモは本物の被害データを使わず、実行時ネットワークを無効にします。準備条件、期待結果、結果の読み方、実データに移る前の制限は[合成デモ手順](safe-demo.md)を参照してください。

## Dockerでの合成データ試験

DockerのLinuxエンジン、PowerShell、ソースコードが必要です。リポジトリ直下から実行します。

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket11 -f tests/safefs/Dockerfile .
./tests/safefs/run.ps1 -Image hwh-safefs-lab:ticket11
```

ビルド時は依存取得の通信を使います。試験実行はネットワークを無効にし、新規Dockerボリュームに無害なテキスト、リンク、特殊ファイル等を用意します。準備処理だけに必要な権限を与え、hwhは非特権で実行します。この準備用コンテナに実際の被害データを渡さないでください。

読み取り試作の既知の本文・SHA-256、禁止アクセスの拒否、checkの端末・JSON・終了状態を検証します。[読み取り試験結果](ticket01-validation.md)と[checkの試験結果](ticket02-validation.md)を参照してください。

結果は`test-artifacts/`の実行別ディレクトリに保存されます。生ログには環境情報が含まれるため公開しません。結果回収後、その実行が作成したコンテナとボリュームを削除します。異常終了で残った場合は、`hwh.safefs.lab=ticket01`ラベルと自分の実行に属する資源を確認して扱ってください。既存ハーネスとの互換性のためラベル・実行名の接頭辞はticket01のままです。

読み取り試験を省略・限定する例（scan試験も実行します）:

```powershell
./tests/safefs/run.ps1 -Image hwh-safefs-lab:ticket11 -CheckOnly
./tests/safefs/run.ps1 -Image hwh-safefs-lab:ticket11 -TestPattern TestF02
```

後者でも独立probe監査とcheck試験は実行します。イメージを省略した場合の既定タグは互換性のため`ticket01`です。新しいコードの検証では明示したタグを使ってください。

## 表示だけ確認する

マウント条件は緩めません。画面の確認だけなら、対象を開かない `preview` を使います。出る候補は合成データです。終了コード 0 は探索成功でも候補なしでもありません。

```sh
./bin/hwh preview
./bin/hwh preview --json
./bin/hwh preview --no-joke
```

`--json` の `command` は `preview`、`reason` は `preview_sample`、`scan_status` は `not_started` です。`--root`、`--quiet`、`--quick`、`--deep` は受け付けません。

## checkのビルドと操作

最初に試す合成コピーの載せ方は[README](../README.md)の「儀式」を参照してください。信頼できるLinux環境で固定版Goを使ってビルドする例です。Dockerイメージ内にも同じCLIを`/opt/hwh`としてビルドします。

```sh
CGO_ENABLED=0 go build -trimpath -o bin/hwh ./cmd/hwh
./bin/hwh --help
./bin/hwh --version
./bin/hwh check --root /mnt/evidence
./bin/hwh check --root /mnt/evidence --json
./bin/hwh check --root /mnt/evidence --quiet
```

`/mnt/evidence`は説明用のパスです。[利用条件](supported-environments.md)を満たす静的な合成コピーを別途準備してください。hwhはマウントや権限変更をしません。rootユーザー、対応外FS、マウント保護不足、必須機能を確認できない場合は拒否します。

通過時は「実行条件の検査を通過」と表示して終了コード0、起動拒否は理由を表示して3です。本文と配下の一覧は読みません。JSONの`scan_status`は常に`not_started`、`findings`は空配列です。候補なし・侵害なしの判定ではありません。通常の失敗理由はstderr、JSONはstdoutへ一つだけ出します。完全な引数・シグナル・出力切断・JSONの定義は[CLI共通契約](cli-contract.md)を参照してください。

`scan`は毎回条件を再検査します。以前のcheck成功をその後の探索許可として保存・流用しません。


## quick探索

```sh
./bin/hwh scan --root /mnt/evidence
./bin/hwh scan --root /mnt/evidence --json
./bin/hwh scan --root /mnt/evidence --quiet
./bin/hwh scan --root /mnt/evidence --deep --json
./bin/hwh scan --root /mnt/evidence --no-joke
./bin/hwh scan --root /mnt/evidence --no-hope
```

[名前ルール](name-rules.md)と[内容ルール](content-rules.md)による候補のパス・属性・理由を示します。1MiB未満・単一リンクで読み取れる候補には完全SHA-256を付けます。同じ完全ハッシュの候補は代表、観測コピー数、保持できた各パスへ[上限付きで集約](deduplication.md)します。ハッシュなしはまとめません。本文の抜粋は表示しません。取得できない理由と本文の取得状態を別に示します。候補0件なら0、候補ありなら1、上限や項目エラーによる部分結果は2です。拒否・障害・中断は[共通契約](cli-contract.md)の別コードです。quietは0/1の出力を抑制します。部分結果・障害はquietでも理由をstderrに表示します。JSONは常にstdoutの1オブジェクトです。候補保持後に停止した場合も、保持済み結果と不完全状態を同じレポートで返します。[組み合わせの検証結果](ticket09-validation.md)も参照してください。

既定の探索範囲は`quick`です。`--quick`の明示も同じ動作です。起点直下を深さ1として最大4まで探索し、指定root直下のみ深さ1です。`--deep`は指定root全体を一起点として深さ64まで探索し、列挙20万・本文512MiB・協調期限300秒の初期予算を使います。`--quick`と`--deep`は併用できません。各モードの範囲と状態を`origins`へ記録し、リンク・別マウントは辿りません。[quick契約](quick-search.md)と[deep契約](deep-search.md)を参照してください。候補数と除外数・列挙数を別に示します。候補0件でも安全ではありません。

通常表示は要約、起点、候補、除外、エラーの順です。候補はパスの次の行に属性を分けます。端末のときだけ見出しに色が付きます。パイプ先、`--json`、`NO_COLOR`、`TERM=dumb` では色はありません。色は装飾で、結果の意味は変えません。`JOKE[detective]`と`JOKE[fortune]`は既定で末尾へ付きます。探索結果・範囲・理由・終了コードは変えません。`--no-joke`で外します。`--no-hope`はhelpに出ない追加行です。JSONとquietでは受理しても表示しません。演出による待ち時間もありません。詳しい契約は[CLI共通契約](cli-contract.md)を参照してください。

scan統合試験だけを繰り返す開発用指定:

```powershell
./tests/safefs/run.ps1 -Image hwh-safefs-lab:ticket11 -ScanOnly
```

大規模な資源・検出品質評価は通常回帰と分けて実行します。20万項目と512MiB本文境界を含みます。

```powershell
./tests/evaluation/run.ps1 -Image hwh-safefs-lab:ticket11
```

方法・事前基準・一般化できない範囲は[評価方法](evaluation-method.md)、実測値は[11の評価結果](ticket11-validation.md)を参照してください。

## fuzz試験

パス入力、mountinfo解析、安全なパス表示のfuzzは、合成バイト列だけを使い、対象ファイルを開きません。通常回帰とは別に、固定したLinux試験イメージから実行します。

```powershell
./tests/fuzz/run.ps1 -Image hwh-safefs-lab:ticket12 -FuzzTime 30s
```

`FuzzTime`は各fuzz対象の実行時間です。実行時ネットワークを無効にし、非root・capabilitiesなしの子プロセスで3対象を順番に実行します。結果は`test-artifacts/hwh12-fuzz-<id>/fuzz.txt`へ保存されます。失敗時にGoが生成する再現入力は、コンテナ内の使い捨てソースコピーにだけ書き込まれます。失敗ログをそのまま公開せず、合成入力であることと環境固有情報がないことを確認してから最小再現例を試験コーパスへ追加してください。

## ローカル配布候補

縮小後の初期対応（Linux amd64 / ext4）向けに、固定依存の実行体とSHA-256をローカル生成して照合する手順です。判定は[ローカル配布候補](release-candidate.md)を参照してください。

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket14 -f tests/safefs/Dockerfile .
./tests/release/run.ps1 -Image hwh-safefs-lab:ticket14
```

成果物の`hwh-linux-amd64`そのもので`--version`、`check`、quick、deepを合成コピーへ実行します。arm64クロスビルドはコンパイル確認だけであり、配布物にも対応環境にも含めません。バイナリは`test-artifacts/`へ回収し、Gitへ追加しません。
