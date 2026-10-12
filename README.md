# hwh — Hacker Was Here

犯人はこの中にいる……とは限りません。

退避コピーから身代金要求文や置き手紙っぽいものを探す、それっぽいジョークツールです。画面は調査した気分になれます。保障はしません。候補が出ても、出なくても、それで判断しないでください。侵害の有無も、攻撃ファミリーも、障害原因もわかりません。

動くのは `hwh check` と `hwh scan` です。`check` は「この部屋に入ってよいか」だけ見ます。本文は読みません。`scan` は名前と小さい本文を拾って、それっぽい候補にハッシュを付けます。通常表示は最初からジョーク付き。ジョークなんて見たくない人は `--json`、`--quiet`、または `--no-joke`。見た目だけなら `hwh preview`。対象は開きません。

合成データでは動きました。本物の被害コピーで遊ぶ段階ではありません。`.deb` は手元で作れます。aptのリポジトリは付いていません。Windows 本体では動きません。

## 儀式

Linux amd64、リポジトリ直下、Go あり。作者が自分で焼く手順です。利用条件は[LICENSE](LICENSE)を参照してください。

```sh
CGO_ENABLED=0 go build -trimpath -o bin/hwh ./cmd/hwh
./bin/hwh --help
./bin/hwh preview
```

`preview` は合成の画面確認です。マウントしていなくても出ます。本物の検査ではありません。

ホームや `/` を突っ込むと、すぐ追い返されます。WSL の `/mnt/c` や `/mnt/d` もext4じゃないのでダメです。自分で偽物の現場を作り、読み取り専用で封をしてから渡してください。hwh は封をしません。

```sh
mkdir -p ~/hwh-lab/copy ~/hwh-lab/mnt
printf 'pay bitcoin to recover files\ncontact us\n' > ~/hwh-lab/copy/README.blacksuit.txt
echo '普通のメモ' > ~/hwh-lab/copy/notes.txt
sudo mount --bind ~/hwh-lab/copy ~/hwh-lab/mnt
sudo mount -o remount,bind,ro,nodev,nosuid,noexec ~/hwh-lab/mnt
./bin/hwh check --root "$HOME/hwh-lab/mnt"
./bin/hwh scan --root "$HOME/hwh-lab/mnt"
./bin/hwh scan --root "$HOME/hwh-lab/mnt" --json
./bin/hwh scan --root "$HOME/hwh-lab/mnt" --no-joke
sudo umount ~/hwh-lab/mnt
```

`check` が通っても、現場は無事ではありません。単に入室許可が出ただけです。本物の被害データや本番サーバーは持ってこないでください。細かい門番ルールは[対応環境](docs/supported-environments.md)、長い手順は[使い方](docs/usage.md)にあります。

## 使い方と制限

- [試作のビルドと合成データでの試験](docs/usage.md)
- [実データを持ち込む前の無害な合成デモ](docs/safe-demo.md)
- [CLI・終了コード・JSONの契約](docs/cli-contract.md)
- [検証済み環境と制限事項](docs/supported-environments.md)

信頼できるLinux調査環境から、明示した静的・読み取り専用コピーを非特権で見る設計です。対象の取得・マウント・復旧、稼働中の本番サーバーの探索は扱いません。

## チケットとか

- [脅威モデルと安全要件](docs/threat-model.md)
- [ファイルアクセスと環境検査の設計](docs/safe-file-access-design.md)
- [受け入れ試験仕様](docs/security-acceptance-tests.md)
- [試作の検証結果と再現方法](docs/ticket01-validation.md)
- [checkの検証結果と残る範囲](docs/ticket02-validation.md)
- [scanの検証結果と残る範囲](docs/ticket03-validation.md)
- [初期名前ルール](docs/name-rules.md)
- [内容ルールと限界](docs/content-rules.md)
- [内容検出の検証結果](docs/ticket06-validation.md)
- [本文取得とハッシュの契約](docs/body-read-contract.md)
- [本文取得の検証結果](docs/ticket04-validation.md)
- [quickの起点・予算・公平性](docs/quick-search.md)
- [quickの検証結果](docs/ticket05-validation.md)
- [deepの範囲と予算](docs/deep-search.md)
- [deepの検証結果](docs/ticket07-validation.md)
- [候補のハッシュ集約](docs/deduplication.md)
- [ハッシュ集約の検証結果](docs/ticket08-validation.md)
- [途中終了と結果状態の検証結果](docs/ticket09-validation.md)
- [表示専用ジョークの検証結果](docs/ticket10-validation.md)
- [資源予算と検出品質の評価方法](docs/evaluation-method.md)
- [資源予算と検出品質の評価結果](docs/ticket11-validation.md)
- [対応環境横断検証](docs/ticket12-validation.md)
- [無害な合成デモの検証結果](docs/ticket13-validation.md)
- [ローカル配布候補](docs/release-candidate.md)
- [ローカル配布候補の検証結果](docs/ticket14-validation.md)
- [メッセージ配置場所の調査と出典](docs/research-note-locations.md)

Goとgolang.org/x/sys/unixを使い、対象の実行・書換え・外部送信をしない方針です。

候補なしは「安全」を意味しません。見落とし・誤検出があり得ます。侵害判定、復旧、証拠保全、OS自体の安全性は保証しません。業務判断の根拠にしないでください。

文書の管理方針は[公開範囲の規則](docs/documentation-policy.md)を参照してください。著作権は留保し、利用許諾は与えていません。詳細は[LICENSE](LICENSE)を参照してください。初期対応は検証済みのLinux amd64/ext4に限定します。[ローカル配布候補](docs/release-candidate.md)を参照してください。問題報告は[SECURITY.md](SECURITY.md)を参照してください。
