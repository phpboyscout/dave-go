package frame

import (
	"bytes"
	"math"
	"strconv"
	"testing"
)

var reviewKey = bytes.Repeat([]byte{7}, 16)

// C-2. Correct: ValidateRanges rejects a range whose offset+length overflows
// int. Trigger: Offset math.MaxInt, Length 1; the sum wraps negative on every
// architecture, so this is red on 64-bit as well as 32-bit.
func TestReview_C2_ValidateRangesMustRejectIntOverflow(t *testing.T) {
	r := Range{Offset: math.MaxInt, Length: 1}
	if err := ValidateRanges([]Range{r}, 16); err == nil {
		t.Errorf("C-2: ValidateRanges accepted {Offset: MaxInt, Length: 1} for a 16-byte frame (offset+length wraps to %d); want ErrInvalidRanges",
			r.Offset+r.Length)
	}
}

// C-2. Correct: Encrypt returns an error for an overflowing range, without
// panicking. Trigger: the same range as above, through the exported API.
func TestReview_C2_EncryptMustNotPanicOnOverflowingRange(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("C-2: Encrypt panicked on range {Offset: MaxInt, Length: 1}: %v; want ErrInvalidRanges", r)
		}
	}()
	if _, err := Encrypt(EncryptParams{Plaintext: make([]byte, 16), Key: reviewKey, TruncatedNonce: 1,
		UnencryptedRanges: []Range{{Offset: math.MaxInt, Length: 1}}}); err == nil {
		t.Error("C-2: Encrypt accepted range {Offset: MaxInt, Length: 1}; want ErrInvalidRanges")
	}
}

// C-2. Correct: Decrypt rejects a wire frame whose range offset is 0x7FFFFFFF,
// without panicking. Trigger: a 16-byte frame with that range in its footer.
// Passes on 64-bit; red on 32-bit targets:
//
//	GOARCH=386 go test -run TestReview_C2 ./frame/
func TestReview_C2_DecryptMustNotPanicOnWireRangeOverflow(t *testing.T) {
	footer := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, // tag
		0x01,                         // nonce 1
		0xFF, 0xFF, 0xFF, 0xFF, 0x07, // offset 0x7FFFFFFF
		0x01, // length 1
	}
	pkt := append(append(make([]byte, 16), footer...), byte(len(footer)+3), 0xFA, 0xFA)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("C-2: Decrypt panicked before authentication on int=%d-bit: %v; want an error", strconv.IntSize, r)
		}
	}()
	if _, _, err := Decrypt(DecryptParams{Ciphertext: pkt, Key: reviewKey}); err == nil {
		t.Errorf("C-2: Decrypt accepted range offset 0x7FFFFFFF on int=%d-bit; want an error", strconv.IntSize)
	}
}
