package session

import (
	"fmt"
	"testing"
)

// C-1. Correct: a Welcome naming a cipher suite other than 2 is rejected
// without panicking. Trigger: opcode 30 carrying the four bytes 00 80 00 00
// (suite 0x0080) after select_protocol_ack(1); 0x0000 and 0xFFFF likewise.
func TestReview_C1_WelcomeWithUnknownCipherSuiteMustNotPanic(t *testing.T) {
	cases := map[string][]byte{
		"suite 0x0080": {0x00, 0x80, 0x00, 0x00},
		"suite 0x0000": {0x00, 0x00, 0x00, 0x00},
		"suite 0xFFFF": {0xFF, 0xFF, 0x00, 0x00},
	}
	for name, welcome := range cases {
		t.Run(name, func(t *testing.T) {
			s := New(reviewBot, &reviewCallbacks{})
			s.OnSelectProtocolAck(1)
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("C-1: OnDaveMLSWelcome(%x) panicked: %v; it must reject the Welcome and return", welcome, r)
				}
			}()
			s.OnDaveMLSWelcome(1, welcome)
		})
	}
}

// C-14. Correct: execute_transition activates the pending epoch only for the
// transition it was prepared under. Trigger: Welcome at transition 5 leaves a
// pending epoch; execute_transition(9) arrives.
func TestReview_C14_ExecuteTransitionWithOtherIDMustNotActivatePending(t *testing.T) {
	control, _, _ := reviewTwoMember(t, 5)
	if control.Ready() {
		t.Fatal("SETUP: Welcome at transition 5 activated before execute_transition")
	}
	control.OnDaveExecuteTransition(5)
	if !control.Ready() {
		t.Fatal("SETUP: control execute_transition(5) did not activate the pending epoch")
	}

	s, _, _ := reviewTwoMember(t, 5)
	s.OnDaveExecuteTransition(9)

	if s.Ready() {
		t.Errorf("C-14: execute_transition(9) activated the epoch pending for transition 5 (State %s); want it left pending",
			fmt.Sprintf("%+v", s.State()))
	}
}
