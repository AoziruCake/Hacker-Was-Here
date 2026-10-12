package cli

import "regexp"

// Only bounded, validated UTF-8 supplied by safefs reaches these rules.
// No paths, IO, markup interpretation or instructions are used here.
var encryptionClaim = regexp.MustCompile(`(?i)\b(your\s+files\s+(are|have\s+been)\s+encrypted|we\s+encrypted\s+your\s+files|all\s+your\s+files\s+are\s+encrypted)\b`)
var recovery = regexp.MustCompile(`(?i)\b((decrypt|recover|restore)\s+your\s+files|decryption\s+(key|tool))\b`)
var payment = regexp.MustCompile(`(?i)\b(pay\s+(in\s+)?bitcoin|send\s+bitcoin|pay\s+the\s+ransom|ransom\s+payment)\b`)
var contact = regexp.MustCompile(`(?i)\b(contact\s+us|email\s+us|write\s+to\s+us|contact\s+our\s+team)\b`)

func contentRules(data []byte) (ids, reasons []string) {
	if !encryptionClaim.Match(data) || !recovery.Match(data) {
		return
	}
	if payment.Match(data) {
		ids = append(ids, "content.encryption-recovery-payment")
		reasons = append(reasons, "暗号化の主張・復旧案内・支払い要求の文面が一致。侵害を確定するものではありません。")
	}
	if contact.Match(data) {
		ids = append(ids, "content.encryption-recovery-contact")
		reasons = append(reasons, "暗号化の主張・復旧案内・連絡要求の文面が一致。侵害を確定するものではありません。")
	}
	return
}
