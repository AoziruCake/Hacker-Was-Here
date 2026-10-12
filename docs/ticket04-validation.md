# 名前候補の本文・ハッシュ: 検証結果

検証日: 2026-10-10。Linux amd64、WSL2系6.18カーネル、Docker管理ボリュームのext4、ro/nodev/nosuid/noexec、UID/GID1000・capabilitiesなし。Go 1.27.2 / x/sys v0.49.0 / CGO無効。合成データのみ。arm64実機・XFS・下限カーネルは未検証。

## 実装範囲

直下の名前候補に[本文契約](body-read-contract.md)を適用。属性検査したpinを保持したまま本文FDを取得し、同じFDのデータから完全SHA-256とテキスト分類を得る。再帰・内容ルールによる候補追加・ハッシュ集約は未実装。本文・抜粋は表示しない。

## 方法と結果

| 試験 | 結果と観測 |
|---|---|
| 公開CLI正常取得 | `abc`の既知SHA-256、空ファイル、BOM、HTML原文、不正UTF-8、UTF-16、NUL含有を確認。完全取得とテキスト分類を分離、抜粋null |
| R01 | 1MiB−1の完全ハッシュ。1MiB・1MiB+1・1TiB sparseは本文open/readなし、file_size_limit、ハッシュnull |
| R02 | 65個の1MiB−1候補で64個を取得。実読取64×(1MiB−1)バイト、次の本文open前にtotal_read_bytes、partial/incomplete。残予算と開始時サイズが同じ場合もopenなし |
| F04/F05/F06 | リンク・FIFO/socket/char/block・ハードリンクの禁止本文アクセスなしを既存probe/scan監査で確認。読取権限なし候補は名前保持、permission_denied、partial |
| F07/F08/F10/F12 | 既存の差替え・再取得失敗・同一性不一致・EAGAIN再試行2回を共有読取経路で回帰。新しい探索境界でも型/dev/inode/mount不一致でread前停止・空結果 |
| R05 | 探索境界でread後のsize/mtime/ctime/nlink/マウントflags変化を注入。本文・ハッシュを捨てて全体停止。総量到達と変化の同時発生でも変化を優先 |
| F09・中断 | 探索境界の失敗・cancel・panicでpin/bodyの解放を確認。既存反復寿命試験も合格。公開CLIで本文read中SIGTERMは143、未完了・ハッシュnull。出力切断は7 |
| 公開CLI本文故障 | baseline traceから本文open/read/statx位置を求め、straceでEIO/ENOSYSを注入。I/Oは6、機能喪失は4、incomplete、名前候補は保持しハッシュnull |
| 全回帰 | F01–F12、17独立probe、check、直下scan/E10、追加本文境界・公開CLI試験が合格。既存の期限・出力予算・禁止アクセス監査を維持 |
| 静的検証 | go vet、Linux arm64とWindows amd64クロスビルド成功。実機検証を意味しない |

独立syscall監査は対象への直接本文open、対象外・下位階層アクセス、mmap、外部実行・通信を拒否する。04では名前候補の本文アクセスだけを許可し、本文openには生存中のpinからのproc再取得を要求する。負の対照も維持。FD上限32と終了時の探索所有FD解放を確認した。最終コードでの全回帰が合格した。

名前列挙20,000件の参考RSSは41,416KiB。本文最大RSSや性能目標の実証ではない。11で512MiB本文境界等を[別途評価](ticket11-validation.md)した。同期I/Oの強制中断、観測できない変更、コピー全体の時点一貫性は保証しない。

## 再現

```powershell
docker build --progress plain -t hwh-safefs-lab:ticket04 -f tests/safefs/Dockerfile .
./tests/safefs/run.ps1 -Image hwh-safefs-lab:ticket04
```

準備コンテナは合成データ専用。実行時ネットワークなし、新規ボリューム、結果回収後はその実行の資源だけを削除する。生ログ・実行IDは公開しない。[使い方](usage.md)と[対応環境](supported-environments.md)を参照。
