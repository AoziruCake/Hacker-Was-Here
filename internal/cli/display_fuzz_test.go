package cli

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"testing"
)

func FuzzSafePathDisplay(f *testing.F) {
	for _, seed := range []string{
		"note.txt",
		"line\nfake-result",
		"\x1b[31mred",
		"right\u202eto-left",
		string([]byte{0xff, 0xfe, 0xfd}),
		"quote\"slash\\",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		path := pathValue(raw)
		if raw == "" || len(raw) >= 4096 {
			if path != nil {
				t.Fatalf("pathValue(%d bytes) = %+v, want nil", len(raw), path)
			}
			return
		}
		if path == nil {
			t.Fatalf("pathValue(%d bytes) unexpectedly returned nil", len(raw))
		}

		decoded, err := base64.StdEncoding.DecodeString(path.BytesBase64)
		if err != nil || string(decoded) != raw {
			t.Fatalf("base64 is not reversible: decoded=%q err=%v", decoded, err)
		}

		displayed, err := strconv.Unquote(path.Display)
		if err != nil {
			t.Fatalf("display is not a quoted Go string: %q: %v", path.Display, err)
		}
		want := raw
		if len(want) > 256 {
			want = want[:256]
		}
		if displayed != want {
			t.Fatalf("display decodes to %q, want %q", displayed, want)
		}
		if path.DisplayTruncated != (len(raw) > 256) {
			t.Fatalf("display_truncated=%t for %d bytes", path.DisplayTruncated, len(raw))
		}
		for _, b := range []byte(path.Display) {
			if b < 0x20 || b > 0x7e {
				t.Fatalf("display contains unsafe non-ASCII byte 0x%02x: %q", b, path.Display)
			}
		}

		encoded, err := json.Marshal(path)
		if err != nil || !json.Valid(encoded) {
			t.Fatalf("invalid JSON %q: %v", encoded, err)
		}
	})
}
