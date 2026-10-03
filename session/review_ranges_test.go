package session

import (
	"strconv"
	"testing"
)

// C-2. Correct: Session.Decrypt rejects a frame whose unencrypted range
// overflows int, without panicking. Trigger: any participant's frame with a
// range offset 0x7FFFFFFF, length 1. Passes on 64-bit, where the sum does not
// overflow; red on 32-bit targets:
//
//	GOARCH=386 go test -run TestReview_C2 ./session/
func TestReview_C2_DecryptMustNotPanicOnRangeOverflow(t *testing.T) {
	s, _, _ := reviewTwoMember(t, 0)
	footer := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, // tag
		0x01,                         // nonce 1
		0xFF, 0xFF, 0xFF, 0xFF, 0x07, // offset 0x7FFFFFFF
		0x01, // length 1
	}
	pkt := append(append(make([]byte, 16), footer...), byte(len(footer)+3), 0xFA, 0xFA)

	defer func() {
		if r := recover(); r != nil {
			t.Errorf("C-2: Session.Decrypt panicked on int=%d-bit: %v; want an error", strconv.IntSize, r)
		}
	}()
	if _, err := s.Decrypt(reviewPeer, pkt, make([]byte, 64)); err == nil {
		t.Errorf("C-2: Session.Decrypt accepted a frame with range offset 0x7FFFFFFF on int=%d-bit; want an error", strconv.IntSize)
	}
}
