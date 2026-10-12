# 初期名前ルール

`scan`は指定ルート直下の通常ファイル名だけを照合する。検出理由は名前だけであり、攻撃ファミリー・侵害の有無を確定しない。ルールIDは報告例を識別するラベルである。

| ID | 条件 | 一致例 | 根拠 |
|---|---|---|---|
| `name.blacksuit-readme` | `README.blacksuit.txt`との完全一致 | `README.blacksuit.txt` | 配置調査R1 |
| `name.play-readme` | `PLAY_Readme.txt`との完全一致 | `PLAY_Readme.txt` | 配置調査R2 |
| `name.crypted-restore` | 空でない接頭辞＋`.crypted.README_TO_RESTORE` | `data.crypted.README_TO_RESTORE` | 配置調査R4 |

出典と事例の適用範囲は[配置調査](research-note-locations.md)を参照。ASCIIのA–Zのみ小文字化して比較する。この大小文字の許容は製品上の判断で、Unicode正規化・ロケール依存の変換は行わない。`README.txt`、`AGENTS.md`、`index.html`、接頭辞のない`.crypted.README_TO_RESTORE`は一致しない。

名前を偽装できるため誤検出があり、未登録の名前・下位階層・削除済みのメッセージを見落とす。リンク・特殊ファイルは名前が一致しても候補にしない。ハードリンクの通常ファイルは名前候補として保持するが、`hardlink_excluded`も計上し、内容とハッシュは取得しない。04では取得完了した本文に`content_status=complete`と完全SHA-256を付ける。本文未取得は`name_only`と`content_reason`、抜粋は常にnull。詳細は[本文契約](body-read-contract.md)。
