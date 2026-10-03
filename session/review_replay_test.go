package session

import (
	"bytes"
	"testing"
	"time"
)

// C-3. Correct: no (key, nonce) pair is ever used twice by the bot's sender.
// Trigger: a bare prepare_transition(0) to an established two-member session,
// then the default 10 s send retention elapses. The sleep is the finding's own
// timeout; there is no public option to shorten the send TTL.
func TestReview_C3_RepeatedSoleMemberTransitionMustNotReuseNonce(t *testing.T) {
	s, _, _ := reviewTwoMember(t, 0)
	p1 := bytes.Repeat([]byte{0x5a}, 32)
	p2 := bytes.Repeat([]byte{0xa5}, 32)

	c1 := reviewEncrypt(t, s, p1)
	s.OnDavePrepareTransition(0, 1)
	time.Sleep(epochRetention + 500*time.Millisecond)
	c2 := reviewEncrypt(t, s, p2)

	reused := true
	for i := range p1 {
		if c1[i]^c2[i] != p1[i]^p2[i] {
			reused = false

			break
		}
	}
	if reused {
		t.Errorf("C-3: keystream reused: c1^c2 == p1^p2 over %d bytes, footers %x and %x (same key and nonce); want a fresh nonce or key",
			len(p1), c1[len(p1):], c2[len(p2):])
	}
}

// C-3. Correct: a frame already accepted is never accepted again in the same
// epoch. Trigger: a bare prepare_transition(0) to an established session
// rebuilds every sender's replay window.
func TestReview_C3_RepeatedSoleMemberTransitionMustNotReopenReplayWindow(t *testing.T) {
	s, peer, _ := reviewTwoMember(t, 0)
	f := peer.frame(t, 1, []byte("hello from peer"))
	buf := make([]byte, 64)
	if _, err := s.Decrypt(reviewPeer, f, buf); err != nil {
		t.Fatalf("SETUP: first decrypt: %v", err)
	}
	if _, err := s.Decrypt(reviewPeer, f, buf); err == nil {
		t.Fatal("SETUP: immediate replay accepted before the trigger")
	}

	s.OnDavePrepareTransition(0, 1)

	if n, err := s.Decrypt(reviewPeer, f, buf); err == nil {
		t.Errorf("C-3: replayed frame accepted after prepare_transition(0) (decrypted %q); want ErrDecryptionFailed", buf[:n])
	}
}

// C-7. Correct: a replay of an already-accepted frame is rejected however old
// it is. Trigger: nonces 1..100 accepted, then nonce 1 replayed (99 behind).
func TestReview_C7_ReplayOlderThanWindowMustBeRejected(t *testing.T) {
	s, peer, _ := reviewTwoMember(t, 0)
	buf := make([]byte, 64)
	frames := make([][]byte, 0, 100)
	for n := uint32(1); n <= 100; n++ {
		f := peer.frame(t, n, []byte{byte(n), 1, 2, 3})
		frames = append(frames, f)
		if _, err := s.Decrypt(reviewPeer, f, buf); err != nil {
			t.Fatalf("SETUP: decrypt nonce %d: %v", n, err)
		}
	}
	if _, err := s.Decrypt(reviewPeer, frames[99], buf); err == nil {
		t.Fatal("SETUP: in-window replay accepted")
	}

	if n, err := s.Decrypt(reviewPeer, frames[0], buf); err == nil {
		t.Errorf("C-7: replay of nonce 1 after nonce 100 accepted (decrypted %x); want rejected", buf[:n])
	}
}

// C-10. Correct: a retained epoch stops decrypting once its 10 s retention
// has passed. Trigger: the peer's epoch-1 frame, a commit to epoch 2, then
// 10.5 s with no further activation. The sleep is the finding's own timeout;
// epochRetention is a constant with no option.
//
// The commit has no proposals (see R-10); if empty commits are later refused,
// this test reports SETUP and needs a proposal-carrying commit instead.
func TestReview_C10_RetainedEpochMustNotDecryptAfterRetention(t *testing.T) {
	s, peer, _ := reviewTwoMember(t, 0)
	inRetention := peer.frame(t, 1, []byte("old epoch audio"))
	oldFrame := peer.frame(t, 2, []byte("old epoch audio"))
	oldEpoch := s.State().EpochID

	s.OnDaveMLSPrepareCommitTransition(5, peer.emptyCommit(t))
	s.OnDaveExecuteTransition(5)
	if got := s.State().EpochID; got == oldEpoch || got != peer.epoch(t) {
		t.Fatalf("SETUP: epoch did not advance to the peer's (bot %d, was %d, peer %d; stats %+v)", got, oldEpoch, peer.epoch(t), s.Stats())
	}
	buf := make([]byte, 64)
	if _, err := s.Decrypt(reviewPeer, inRetention, buf); err != nil {
		t.Fatalf("SETUP: old-epoch frame rejected inside the retention window: %v", err)
	}
	time.Sleep(epochRetention + 500*time.Millisecond)

	if n, err := s.Decrypt(reviewPeer, oldFrame, buf); err == nil {
		t.Errorf("C-10: epoch-%d frame decrypted %v after epoch %d activated (%q); want rejected after 10 s",
			oldEpoch, epochRetention+500*time.Millisecond, s.State().EpochID, buf[:n])
	}
}
