# CLI共通契約 v1

`check`とquick/deep探索`scan`の公開契約を定める。`preview`は表示確認専用で、探索契約には含めない。通常表示は日本語、JSONキー・状態・理由IDは英語固定。名前候補の本文取得・ハッシュを04、内容ルールを06、deepを07、ハッシュ集約を08、表示専用ジョークを10で追加した。

## 操作と引数

```sh
hwh check --root /mnt/evidence
hwh check --root=/mnt/evidence --json
hwh check --root /mnt/evidence --quiet
hwh preview
hwh preview --json
hwh preview --no-joke
hwh --help
hwh check --help
hwh scan --help
hwh preview --help
hwh --version
```

`preview`は固定の合成結果を、scanと同じ通常表示とJSONへ流す。対象パス、mount、safefsは開かない。マウント条件は緩和しない。成功時のプロセス終了コードは0で、scanの「候補0件」ではない。JSONの`command`は`preview`、`reason`は`preview_sample`、`message`は「合成表示です。実対象の探索結果ではありません。」、`scan_status`は`not_started`、`exit_code`は0。通常表示の先頭は`preview: 合成表示です。実対象の探索結果ではありません。`である。`--root`、`--quiet`、`--quick`、`--deep`は引数エラー。ジョーク指定はscanと同じで、JSONでは表示しない。

`check`のrootは一つ必須。絶対パス、4096バイト未満、NUL・空成分・`.`・`..`を拒否し、末尾スラッシュ一つだけを許す。ホスト`/`と同じ実体、経路中のリンクも拒否する。相対パスをカレントディレクトリから補完しない。

オプションの重複、位置引数、未知のオプション、boolへの値指定、`--json`と`--quiet`の併用は引数エラー。`check`に`--quick`/`--deep`とジョーク指定（`--detective`、`--fortune`、`--no-hope`、`--no-joke`）を付けてもエラー。helpは`hwh --help`、`hwh check --help`、`hwh scan --help`、`hwh preview --help`、versionは上記単独形式だけ。help/versionと他オプションの併用もエラー。scanはquickが既定で、`--quick`も受け付ける。deepは`--deep`で明示し、quick/deep同時指定は引数エラー。ジョーク指定の契約は末尾の「10: 表示専用ジョーク」を参照する。

引数エラー時も独立した`--json`トークンがあればJSONを返す（root値として消費したトークンを含む場合も形式選択のため検知する）。未知の引数やOSの生エラーメッセージは表示しない。rootだけを後述の安全な形式で表示する。

## 終了コードと優先順位

| コード | check | scan |
|---:|---|---|
| 0 | 実行条件通過、help/version成功 | 完了・候補0 |
| 1 | 使用しない | 完了・候補あり |
| 2 | 使用しない | 予算・権限不足等で不完全。候補があっても2を優先 |
| 3 | 引数不正または起動条件拒否 | 起動拒否、探索未開始 |
| 4 | 内部エラー | `security_invariant_failed`または`internal_error`で停止 |
| 5 | 観測された環境・対象変化 | 対象・環境変化で全体停止 |
| 6 | 検査中のI/O障害 | I/O障害で全体停止 |
| 7 | stdout/stderrへの出力失敗 | 同左。切れたJSONの完結は保証しない |
| 130 / 143 | SIGINT / SIGTERMによる協調中断 | 同左、保持できた候補と不完全状態を可能なら出力 |

優先順位は出力失敗7 > 内部異常4 > 変化5 > I/O障害6 > シグナル130/143 > 拒否3 > 不完全2 > 候補あり1 > 0。シグナルが複数到着した場合、処理が認識した最初のものを採用。SIGKILL、ランタイムの回復不能障害、停止したカーネルI/Oについて結果出力・終了期限を保証しない。

`target_changed`は対象の消失・同一性や版の不一致、`environment_changed`はマウント等の実行条件の変化を表す。どちらも全体停止とし、変化した対象の本文・ハッシュを捨てる。列挙済み対象の消失や再取得の不一致を単件スキップして完了扱いにしない。あらかじめ定義された任意起点が最初から存在しない場合だけ、起点状態に`not_present`を記録する。必須rootの未存在は起動拒否。探索開始後に必須機能を失った場合は`security_invariant_failed`、予期しない実装障害は`internal_error`とする。

## 出力先

JSONはstdoutへ単一オブジェクトと末尾改行を出す。正常・拒否・引数エラーともstderrに補助テキストを混ぜない。checkの通常表示は成功をstdout、失敗をstderrへ出す。quietはcheck成功時の通常表示を抑え、失敗理由はstderrへ残す。scanでも通常の候補表示を抑えるが、不完全・停止の固定説明はstderrへ残す契約とする。help/versionはstdout。

結果はメモリで完成してから出力する。checkの出力量は16KiB以下。出力途中の切断は7で停止し、再送や別チャネルへのJSON書き直しはしない。JSON内のexit_codeは出力前に決定した値であり、出力に失敗した場合はプロセスの終了コード7を優先する。

## checkのJSON

常に次のキーを持つ。スキーマ版は整数1。v1では意味・型の破壊的変更を行わず、新版で変更する。利用側は未知の追加キーを無視できるようにする。

| キー | 型・意味 |
|---|---|
| schema_version | 1 |
| command | check。未知コマンドも拒否レポートの形式はcheck契約で返す |
| status | passed / rejected / interrupted / failed |
| reason | conditions_passed、invalid_arguments、invalid_root、privileged_execution、unsupported_environment、unsupported_mount、permission_denied、environment_changed、io_error、internal_error、interrupted |
| message | 通常表示と共通の固定説明。機械判定にはreasonを使う |
| exit_code | 出力前に決定した終了コード |
| scan_status | 常にnot_started。checkは探索を行わない |
| root | 下記パスオブジェクト、未指定・4096バイト以上ならnull |
| findings | 常に空配列。候補なしの証明ではない |
| finished_at | UTC、RFC3339Nanoの文字列。ホスト時計の値であり証拠時刻の保証ではない |

root未指定時の例（時刻は説明用）:

```json
{"schema_version":1,"command":"check","status":"rejected","reason":"invalid_root","message":"対象ルートには / 以外の有効な絶対パスを指定してください。リンクを含む経路も使用できません。","exit_code":3,"scan_status":"not_started","root":null,"findings":[],"finished_at":"2026-10-10T00:00:00Z"}
```

終了コードは結果の完全性を優先する。例えば将来のscanで候補が3件あっても予算到達なら2、対象変化なら5。表示に失敗した場合はその結果にかかわらず7とする。単に「候補あり」を成功判定として採用しないための契約である。

## パスと日時・欠落属性

rootは利用者が指定した元のパス（不正な相対パスも拒否結果に含む）、scan候補はrootからの相対パス。表示用の結合や正規化から元バイト列を推測しない。

パスオブジェクトは`display`（ASCII引用文字列）、`bytes_base64`（元バイト列をRFC4648標準Base64で符号化）、`display_truncated`（bool）。displayは先頭256バイトをGo形式で引用し、非ASCII・制御文字・不正UTF-8をエスケープする。切り詰めてもbytes_base64は全バイトを保持する。displayからパスを再構築せずBase64を復号する。JSON自体は標準シリアライザで生成する。

日時はUTCのRFC3339Nano。取得不能なサイズ・更新時刻・SHA-256等の属性はnullで表し、0、空文字、現在時刻で代用しない。checkはファイル属性を取得して候補化しないため、候補属性自体を出さない。

## scanのスキーマと集約・秘匿

scanは共通キーに加えて次を持つ。checkの出力には追加しない。

- status: completed / partial / rejected / interrupted / failed。scan_status: completed / incomplete / not_started。completedでも方針上の除外はあり得る。scanのreasonには共通の完了・拒否理由に加え、`budget_exceeded`、`entry_errors`、`target_changed`、`environment_changed`、`security_invariant_failed`、`io_error`、`interrupted`、`internal_error`を使用する。
- findings: 候補グループ配列。各要素はrepresentative_path、paths、paths_truncated、copy_count、rule_ids、size_bytes、mtime、sha256、content_status、excerptを持つ。pathsは保持できたパスオブジェクトの配列。content_statusはname_only / complete。未取得属性はnull。
- summary: candidate_count（集約前の検出パス数）、group_count（完全ハッシュ等で集約後のグループ数）、retained_group_count（出力に保持した数）、findings_truncated（bool）。数は観測済み範囲の値で、未探索分を推測しない。
- policy_exclusions: reason/countの配列。errors: reason/pathの配列と詳細切り詰めを示すerrors_truncated。limits: 到達した予算IDの配列。集計も保持も既定予算内に限定する。

集約キーは完全SHA-256。同じハッシュのコピー数をcopy_countへ記録する。ハッシュなしは別グループとして扱い、パスや部分ハッシュでまとめない。代表パスは最初に保持したパスとし、ソートのために全件を保持しない。FS列挙順が違えば代表パスは変わり得る。コピー数は保持したpaths数より大きい場合があり、その際はpaths_truncated=trueとする。理由はグループ内の重複なし和集合である。上限時の詳しい保持規則は[候補のハッシュ集約](deduplication.md)を参照。

抜粋は端末・JSONとも無効、長さ0、excerpt=nullを初期契約とする。要求文内の連絡先・秘密情報の不用意な再掲を避けるためである。ルールIDと固定説明で根拠を示す。自動的なパス匿名化はしないため、出力の保存先は操作者が保護する。抜粋の将来追加は明示選択・長さ・秘匿方針を改めて決める。

シグナル・内部エラー等では、取得完了済みで検証された候補だけを予算内で保持し、エラーと不完全状態を可能なら一つのレポートに含める。直下scanの試験を03、本文経路を04、完全ハッシュ集約を08で検証した。

## 03で導入したscanと05の更新

`scan --root ABS [--quick | --deep] [--json | --quiet]`を提供する。03の名前・属性探索に04で本文・完全ハッシュ取得、05でquickの優先起点巡回、06で内容ルール、07でdeep、08で完全ハッシュ集約を追加した。`scope`はquickなら`{kind:quick,max_depth:4,content_scanned:true}`、deepなら`{kind:deep,max_depth:64,content_scanned:true}`。`coverage.enumerated_entries`、予約済みのsummary・policy_exclusions・errors・errors_truncated・limitsを出力する。候補には固定文の`reasons`配列も付ける。属性は代表候補のサイズとUTC mtimeで、範囲外mtimeはnull。

完了は[quickの定義範囲](quick-search.md)だけを意味し、`directory_not_scanned`・`symlink_excluded`・`special_file`・`mount_excluded`・`hardlink_excluded`を別集計する。属性取得前の権限拒否はerrorsに記録しpartial。列挙20,000件（ちょうどでも保守的に部分結果）、保持候補2,000件/生パス2MiB、保持エラー200件/生パス256KiB、協調期限30秒。256件ずつ名前を取り出す。名前候補のJSON領域は6MiBまでとし、残り2MiBをエラー・root・サマリー・終端に予約する。全体8MiBを超えない。上限IDは`enumeration_entries`、`candidate_paths`、`candidate_bytes`、`error_paths`、`error_bytes`、`output_bytes`、`deadline`。切り詰め後も列挙予算内の候補数を集計する。

通常表示は0/1でstdout、部分結果・拒否・障害でstderr。見出しは`[要約]`、`[起点]`、`[候補]`、`[除外]`、`[エラー]`の順で、空の節は出さない。要約行は`scope=`、`depth=`、`content_rules=`、`enumerated=`、`candidates=`、`groups=`、`retained_groups=`を空白区切りで残す。起点は`origin=`、除外は`excluded=`、件数行は`errors=`、`errors_truncated=`、`limits=`を残す。候補は代表パスの次行に属性、その次行に`reason=`を出す。`content_rules`は内容判定を開始した場合だけ`scanned`、それ以外は`not_scanned`である。端末かつ`NO_COLOR`が空で`TERM`が`dumb`でないときだけ見出しを色付きにする。色を消しても同じ語が残る。JSONの形は変えない。

quietでは候補明細を抑制するが、部分結果の理由・集計は残す。JSONでは常にstdout。探索開始後の障害・中断はincompleteとし、それまでに取得できた候補を保持する。これはコピー全体の整合性を保証しない。


## 04: 本文取得
名前候補の本文を固定FDから取得し、完全EOFと事後検査後だけSHA-256を付ける。`content_status=complete`は取得完了を意味し、内容ルールによる検出ではない。06では`scope.content_scanned=true`が内容判定を有効にして探索を開始したことを示す（起動拒否時はfalse）。一般名の通常ファイルも取得対象。`detection_basis=name_pattern/content_pattern`で名前一致と内容一致を区別する。[内容ルール](content-rules.md)を参照。追加フィールド・予算・未取得理由は[本文契約](body-read-contract.md)を参照。

## 05: quickの起点と範囲

`origins`は探索開始後に15起点を固定順で出力する。各要素は`path`（プログラム固定の相対パス、ルートは`.`）、`max_depth`（固定ファイル0、root直下1、他4）、`status`（not_started / completed / not_present / excluded / incomplete）、`enumerated_entries`、`read_bytes`。起動拒否時は省略する。実行中断時、未開始と開始済み未完了を区別する。通常表示にも同じ起点情報を示す。

`depth_limit`は予定範囲の方針除外。起点予算・キュー超過は`limits`の`origin_entries`、`origin_read_bytes`、`queued_paths`、`queued_bytes`、`path_bytes`で示す。起点予算超過後も他起点を継続し、最終結果はpartial。列挙は取得した名前を数え、バッチ途中停止時には属性未確認の名前も含む。固定パスの直接照会は列挙数へ加えない。詳細は[quick契約](quick-search.md)。

## 07: deepの範囲

deepは`.`一起点をFIFOで深さ64まで探索する。列挙200,000、本文総量512MiB、協調期限300秒へ切り替え、その他の待ちパス・FD・一ファイル・候補・エラー・出力上限はquickと共通である。起点別上限は適用しない。詳細は[deep契約](deep-search.md)。

## 10: 表示専用ジョーク

`scan`の通常表示は既定で`JOKE[detective]`と`JOKE[fortune]`を付ける。`--no-hope`は隠し指定としてhelpへ掲載せず、指定時だけ3行目を追加する。`--detective`と`--fortune`は既定と同じ行を明示するだけで、helpへ掲載する。`--no-joke`は通常表示から全ジョークを外す。helpへ掲載する。複数指定時は引数順にかかわらずdetective、fortune、no-hopeの順ですべて表示する。各行は`JOKE[...]`で始まり、通常レポートの後に出す。待ち時間、乱数、対象由来データの引用は加えない。

ジョークは探索とReport生成の後に固定文を付ける表示処理だけであり、候補・集約・範囲・理由・終了状態・終了コードを変更しない。`--json`または`--quiet`と併用した場合は指定を受理するが全ジョークを抑制する。`--no-joke`と`--detective`/`--fortune`/`--no-hope`の併用は引数エラーである。引数拒否・起動拒否・完了・候補あり・部分結果・停止の通常表示でも、ジョーク文は安全や非侵害を示さない。各指定の重複と値付き指定は他のboolオプションと同じく引数エラーである。
