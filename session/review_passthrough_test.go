package session

import (
	"bytes"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
)

func reviewAssertNoPlaintextOut(t *testing.T, s *Session, when string) {
	t.Helper()
	if v := s.State().ProtocolVersion; v == 0 {
		t.Fatalf("SETUP: protocol version is 0 %s", when)
	}
	p := []byte("secret audio payload")
	out := make([]byte, 128)
	n, err := s.Encrypt(reviewSSRC, p, out)
	if err == nil && bytes.Equal(out[:n], p) {
		t.Errorf("C-6: Encrypt returned the plaintext unchanged, with no error, %s (ProtocolVersion=%d); want an error or a held frame, never plaintext",
			when, s.State().ProtocolVersion)
	}
}

// C-6. Correct: while the negotiated protocol version is above 0, Encrypt
// never returns plaintext. Three triggers, one per subtest.
func TestReview_C6_EncryptMustNotEmitPlaintextUnderE2EE(t *testing.T) {
	// Case 1 matches golibdave's initial passthrough (read, not measured).
	t.Run("case 1: right after select_protocol_ack(1)", func(t *testing.T) {
		s := New(reviewBot, &reviewCallbacks{})
		s.AssignSsrcToCodec(reviewSSRC, godave.CodecOpus)
		s.OnSelectProtocolAck(1)
		reviewAssertNoPlaintextOut(t, s, "after select_protocol_ack(1)")
	})

	// Sleeps the default 10 s send retention; there is no option to shorten it.
	t.Run("case 2: prepare_epoch(1) on an established session, retention expired", func(t *testing.T) {
		s := reviewSoleMember(t)
		reviewEncrypt(t, s, []byte("before reset"))
		s.OnDavePrepareEpoch(1, 1)
		time.Sleep(epochRetention + 500*time.Millisecond)
		reviewAssertNoPlaintextOut(t, s, "10.5 s after prepare_epoch(1)")
	})

	// In-package: no public message sequence yields an epoch without the bot,
	// so the roster is built directly with the existing setupForActivation fixture.
	t.Run("case 3: activation in which the bot is missing from the roster", func(t *testing.T) {
		s := setupForActivation(t, []godave.UserID{"bot"}, []godave.UserID{"other"})
		s.AssignSsrcToCodec(reviewSSRC, godave.CodecOpus)
		s.mu.Lock()
		s.protocolVersion = 1
		s.activatePendingEpochLocked()
		s.mu.Unlock()
		reviewAssertNoPlaintextOut(t, s, "after an activation without the bot")
	})
}

// C-12. Correct: after a prepare_epoch(1) reset of an established session,
// Decrypt rejects a non-DAVE frame. Only the post-reset case is asserted:
// during the initial handshake golibdave was measured to accept plaintext too.
func TestReview_C12_DecryptMustRejectPlaintextAfterEpochReset(t *testing.T) {
	s, _, _ := reviewTwoMember(t, 0)
	injected := []byte("injected by the SFU, not a DAVE frame")
	if frame.LooksLikeDAVEFrame(injected) {
		t.Fatal("SETUP: injected bytes look like a DAVE frame")
	}
	buf := make([]byte, 64)
	if _, err := s.Decrypt(reviewPeer, injected, buf); err == nil {
		t.Fatal("SETUP: plaintext accepted before the reset")
	}

	s.OnDavePrepareEpoch(1, 1)

	if n, err := s.Decrypt(reviewPeer, injected, buf); err == nil {
		t.Errorf("C-12: plaintext accepted after prepare_epoch(1) with ProtocolVersion=%d (returned %q); want rejected",
			s.State().ProtocolVersion, buf[:n])
	}
}
