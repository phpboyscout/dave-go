package frame

import (
	"bytes"
	"errors"
	"testing"
)

// reviewWithRangeTail re-encodes a one-range frame with extra bytes appended
// to its ranges region and the supplemental size bumped to match.
func reviewWithRangeTail(t *testing.T, tail ...byte) (original, mutated, plaintext []byte) {
	t.Helper()
	plaintext = bytes.Repeat([]byte{0xAB}, 40)
	original, err := Encrypt(EncryptParams{Plaintext: plaintext, Key: reviewKey, TruncatedNonce: 7,
		UnencryptedRanges: []Range{{Offset: 0, Length: 4}}})
	if err != nil {
		t.Fatalf("SETUP: Encrypt: %v", err)
	}
	n := len(original)
	mutated = append(append([]byte(nil), original[:n-3]...), tail...)
	mutated = append(mutated, original[n-3]+byte(len(tail)), 0xFA, 0xFA)

	return original, mutated, plaintext
}

// C-13. Correct: a footer whose ranges region has bytes left over after the
// last complete (offset, length) pair is rejected, as libdave does. Triggers:
// a stray complete ULEB128 (0x00) and a truncated one (0x80).
func TestReview_C13_FooterWithTrailingRangeBytesMustBeRejected(t *testing.T) {
	for name, tail := range map[string][]byte{"stray 0x00": {0x00}, "truncated ULEB128 0x80": {0x80}} {
		t.Run(name, func(t *testing.T) {
			_, mutated, plaintext := reviewWithRangeTail(t, tail...)
			if got, _, err := Decrypt(DecryptParams{Ciphertext: mutated, Key: reviewKey}); err == nil {
				t.Errorf("C-13: footer with trailing range bytes %x accepted; decrypted to the original plaintext: %v; want rejected",
					tail, bytes.Equal(got, plaintext))
			}
		})
	}
}

// C-13. Correct: a non-canonical ULEB128 nonce is rejected, so one frame has
// one wire encoding. Trigger: nonce 1 encoded as 0x81 0x00.
func TestReview_C13_NonCanonicalULEB128NonceMustBeRejected(t *testing.T) {
	plaintext := []byte("opus frame payload")
	original, err := Encrypt(EncryptParams{Plaintext: plaintext, Key: reviewKey, TruncatedNonce: 1})
	if err != nil {
		t.Fatalf("SETUP: Encrypt: %v", err)
	}
	if original[len(plaintext)+8] != 0x01 {
		t.Fatalf("SETUP: canonical nonce byte is %x, want 01", original[len(plaintext)+8])
	}
	mutated := append(append([]byte(nil), original[:len(plaintext)+8]...), 0x81, 0x00)
	mutated = append(mutated, 8+2+1+2, 0xFA, 0xFA)

	if got, nonce, err := Decrypt(DecryptParams{Ciphertext: mutated, Key: reviewKey}); err == nil {
		t.Errorf("C-13: nonce encoded non-canonically as 81 00 accepted (nonce %d, same plaintext: %v); want rejected",
			nonce, bytes.Equal(got, plaintext))
	}
}

// C-13. Correct: Encrypt errors when the supplemental data exceeds the 255
// bytes its one-byte size field can describe. Trigger: 150 one-byte ranges.
func TestReview_C13_EncryptMustErrorWhenSupplementalSizeExceeds255(t *testing.T) {
	ranges := make([]Range, 0, 150)
	for i := range 150 {
		ranges = append(ranges, Range{Offset: i * 2, Length: 1})
	}
	out, err := Encrypt(EncryptParams{Plaintext: make([]byte, 400), Key: reviewKey, TruncatedNonce: 1, UnencryptedRanges: ranges})
	if err == nil {
		_, _, derr := Decrypt(DecryptParams{Ciphertext: out, Key: reviewKey})
		t.Errorf("C-13: Encrypt succeeded with 150 ranges, writing supplemental size byte %d for a footer of more than 300 bytes; its own Decrypt says %v; want an error",
			out[len(out)-3], derr)
	}
}

// R-8. Correct: EncryptInto reports ErrBufferTooSmall when len(dst) cannot
// hold the frame, rather than writing past len(dst) into spare capacity.
// Trigger: len(dst) 0, cap(dst) 256.
func TestReview_R8_EncryptIntoMustCheckLenNotCap(t *testing.T) {
	dst := make([]byte, 0, 256)
	n, err := EncryptInto(dst, EncryptParams{Plaintext: []byte("opus frame payload"), Key: reviewKey, TruncatedNonce: 1})
	if !errors.Is(err, ErrBufferTooSmall) {
		t.Errorf("R-8: EncryptInto with len(dst)=0, cap(dst)=256 returned n=%d, err=%v; want ErrBufferTooSmall", n, err)
	}
}
