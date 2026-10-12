// Package cli implements the public command boundary. It never interprets target content.
package cli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0-dev"

const helpText = `hwh check --root ABSOLUTE_PATH [--json | --quiet]
hwh scan --root ABSOLUTE_PATH [--quick | --deep] [--json | --quiet] [--detective] [--fortune] [--no-joke]
hwh preview [--json] [--detective] [--fortune] [--no-joke]
hwh --help
hwh --version
checkは実行条件のみ確認します。scanは既定でquick、明示時はdeepを探索します。通常表示は既定でジョーク付きです。JSONとquietでは抑制し、--no-jokeで通常表示からも外します。previewは合成結果の表示確認だけで、対象もマウントも開きません。checkとscanのマウント条件は変わりません。`

const previewBanner = "preview: 合成表示です。実対象の探索結果ではありません。"

var ErrTerminated = errors.New("SIGTERM")

type jokeSet struct {
	detective bool
	fortune   bool
	noHope    bool
}

func (j jokeSet) text() string {
	var lines []string
	if j.detective {
		lines = append(lines, "JOKE[detective]: 犯人はこの中にいる……とは限りません。結果は候補です。")
	}
	if j.fortune {
		lines = append(lines, "JOKE[fortune]: 今日の捜査運: 思い込みより記録が吉。")
	}
	if j.noHope {
		lines = append(lines, "JOKE[no-hope]: 希望は未検出です。これは侵害の有無を意味しません。")
	}
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func interruption(ctx context.Context, root string) Report {
	code := 130
	if errors.Is(context.Cause(ctx), ErrTerminated) {
		code = 143
	}
	return result(root, "interrupted", "interrupted", code)
}

type Path struct {
	Display          string `json:"display"`
	BytesBase64      string `json:"bytes_base64"`
	DisplayTruncated bool   `json:"display_truncated"`
}
type Report struct {
	SchemaVersion    int          `json:"schema_version"`
	Command          string       `json:"command"`
	Status           string       `json:"status"`
	Reason           string       `json:"reason"`
	Message          string       `json:"message"`
	ExitCode         int          `json:"exit_code"`
	ScanStatus       string       `json:"scan_status"`
	Root             *Path        `json:"root"`
	Findings         []Finding    `json:"findings"`
	FinishedAt       string       `json:"finished_at"`
	Scope            *Scope       `json:"scope,omitempty"`
	Summary          *Summary     `json:"summary,omitempty"`
	Coverage         *Coverage    `json:"coverage,omitempty"`
	Origins          []Origin     `json:"origins,omitempty"`
	PolicyExclusions *[]Exclusion `json:"policy_exclusions,omitempty"`
	Errors           *[]ScanError `json:"errors,omitempty"`
	ErrorsTruncated  *bool        `json:"errors_truncated,omitempty"`
	Limits           *[]string    `json:"limits,omitempty"`
}

func pathValue(raw string) *Path {
	if raw == "" || len(raw) >= 4096 {
		return nil
	}
	display := raw
	truncated := len(display) > 256
	if truncated {
		display = display[:256]
	}
	return &Path{strconv.QuoteToASCII(display), base64.StdEncoding.EncodeToString([]byte(raw)), truncated}
}
func result(root, status, reason string, code int) Report {
	return Report{SchemaVersion: 1, Command: "check", Status: status, Reason: reason, Message: message(reason), ExitCode: code, ScanStatus: "not_started", Root: pathValue(root), Findings: []Finding{}, FinishedAt: time.Now().UTC().Format(time.RFC3339Nano)}
}
func message(reason string) string {
	switch reason {
	case "budget_exceeded":
		return "探索上限に達しました。結果は一部です。候補0件でも安全を意味しません。"
	case "entry_errors":
		return "属性を確認できない項目があります。結果は一部です。"
	case "scope_completed":
		return "指定した範囲の探索を終了しました。範囲外は未探索です。候補0件でも安全を意味しません。"
	case "conditions_passed":
		return "実行条件の検査を通過しました。安全性・コピーの真正性・侵害の有無を証明するものではありません。"
	case "invalid_root":
		return "対象ルートには / 以外の有効な絶対パスを指定してください。リンクを含む経路も使用できません。"
	case "invalid_arguments":
		return "引数が不正です。hwh --help で使用方法を確認してください。"
	case "privileged_execution":
		return "非root・一致した資格情報・capabilitiesなしの実行が必要です。"
	case "unsupported_mount":
		return "ext4 と ro,nodev,nosuid,noexec のマウント条件が必要です。"
	case "permission_denied":
		return "必要な読み取り権限を確認できません。"
	case "environment_changed":
		return "実行条件の変化を検出したため停止しました。"
	case "target_changed":
		return "探索対象の変化を検出したため停止しました。"
	case "interrupted":
		return "処理を中断しました。"
	case "security_invariant_failed":
		return "探索中に必須の保護条件を維持できなくなったため停止しました。"
	case "internal_error":
		return "内部エラーのため停止しました。"
	case "io_error":
		return "検査中のI/O障害のため停止しました。"
	default:
		return "必要な実行環境・保護機能を確認できません。"
	}
}
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		if _, err := fmt.Fprintln(stdout, "hwh "+Version); err != nil {
			return 7
		}
		return 0
	}
	if (len(args) == 1 && args[0] == "--help") || (len(args) == 2 && (args[0] == "check" || args[0] == "scan" || args[0] == "preview") && args[1] == "--help") {
		if _, err := fmt.Fprintln(stdout, helpText); err != nil {
			return 7
		}
		return 0
	}
	if len(args) > 0 && args[0] == "preview" {
		return runPreview(args, stdout, stderr)
	}
	wantJSON := false
	quiet := false
	jokes := jokeSet{}
	jokeOff := false
	jokeOn := false
	for _, arg := range args {
		if arg == "--json" {
			wantJSON = true
		}
	}
	root := ""
	reason := ""
	mode := "quick"
	quickSelected, deepSelected := false, false
	if len(args) == 0 || (args[0] != "check" && args[0] != "scan") {
		reason = "invalid_arguments"
	} else {
		seen := map[string]bool{}
		for i := 1; i < len(args); i++ {
			name, value, assigned := strings.Cut(args[i], "=")
			if seen[name] {
				reason = "invalid_arguments"
				break
			}
			seen[name] = true
			switch name {
			case "--quick":
				if assigned || args[0] != "scan" {
					reason = "invalid_arguments"
				}
				quickSelected = true
			case "--deep":
				if assigned || args[0] != "scan" {
					reason = "invalid_arguments"
				}
				deepSelected = true
				mode = "deep"
			case "--root":
				if !assigned {
					i++
					if i >= len(args) {
						reason = "invalid_arguments"
						break
					}
					value = args[i]
				}
				root = value
			case "--json":
				if assigned {
					reason = "invalid_arguments"
				}
			case "--quiet":
				quiet = true
				if assigned {
					reason = "invalid_arguments"
				}
			case "--detective", "--fortune", "--no-hope", "--no-joke":
				if assigned || args[0] != "scan" {
					reason = "invalid_arguments"
					break
				}
				switch name {
				case "--detective":
					jokes.detective = true
					jokeOn = true
				case "--fortune":
					jokes.fortune = true
					jokeOn = true
				case "--no-hope":
					jokes.noHope = true
					jokeOn = true
				case "--no-joke":
					jokeOff = true
				}
			default:
				reason = "invalid_arguments"
			}
			if reason != "" {
				break
			}
		}
	}
	if quiet && wantJSON {
		reason = "invalid_arguments"
	}
	if quickSelected && deepSelected {
		reason = "invalid_arguments"
	}
	if jokeOff && jokeOn {
		reason = "invalid_arguments"
	}
	if len(args) > 0 && args[0] == "scan" && !jokeOff {
		jokes.detective = true
		jokes.fortune = true
	}
	if jokeOff {
		jokes = jokeSet{}
	}
	report := result(root, "rejected", reason, 3)
	if reason == "" {
		if root == "" {
			report = result(root, "rejected", "invalid_root", 3)
		} else {
			if args[0] == "scan" {
				report = scan(ctx, root, mode)
			} else {
				report = guardedCheck(ctx, root)
			}
		}
	}
	if len(args) > 0 && args[0] == "scan" && report.Command != "scan" {
		report = scanFailure(root, report, mode)
	}
	if ctx.Err() != nil && priority(report.ExitCode) < priority(130) {
		if report.Command == "scan" {
			report.fail(interruption(ctx, root))
		} else {
			report = interruption(ctx, root)
		}
	}
	return emit(report, wantJSON, quiet, jokes, stdout, stderr)
}

func guardedCheck(ctx context.Context, root string) (report Report) {
	defer func() {
		if recover() != nil {
			report = result(root, "failed", "internal_error", 4)
		}
	}()
	return check(ctx, root)
}

func emit(report Report, wantJSON, quiet bool, jokes jokeSet, stdout, stderr io.Writer) int {
	if quiet && (report.ExitCode == 0 || report.ExitCode == 1) {
		return report.ExitCode
	}
	writer := stdout
	var data []byte
	if wantJSON {
		var err error
		data, err = json.Marshal(report)
		if err != nil {
			return 4
		}
		data = append(data, '\n')
	} else {
		if report.ExitCode != 0 && report.ExitCode != 1 {
			writer = stderr
		}
		text := renderText(report, quiet, jokes, terminal(writer))
		data = []byte(text)
	}
	maxOutput := 16 << 10
	if report.Command == "scan" || report.Command == "preview" {
		maxOutput = 8 << 20
	}
	if len(data) > maxOutput {
		// The bounded root and fixed fields make this unreachable in schema v1.
		return emit(result("", "failed", "internal_error", 4), wantJSON, false, jokeSet{}, stdout, stderr)
	}
	n, err := writer.Write(data)
	if err != nil || n != len(data) {
		return 7
	}
	return report.ExitCode
}
