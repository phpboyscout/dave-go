package session

import (
	"bytes"
	"testing"

	"github.com/thomas-vilte/dave-go/mediakeys"
)

// godave.Session documents that sessions which never establish E2EE always
// report Ready. A channel negotiated at protocol version 0, such as a Stage,
// is one: Discord's voice layers gate sending and receiving on Ready, so a
// session that stays not-ready there carries no audio at all.

func activateTestEpoch(t *testing.T, s *Session) {
	t.Helper()

	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}

	s.mu.Lock()
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
}

func TestReady_TrueOnceVersionZeroIsNegotiated(t *testing.T) {
	s := New("123456789", &kpCapturingCallbacks{})

	// Before the voice gateway has said anything, nothing is known yet, so a
	// sender must not treat the channel as transport-only.
	if s.Ready() {
		t.Fatal("Ready before SELECT_PROTOCOL_ACK = true, want false")
	}

	s.OnSelectProtocolAck(0)

	if !s.Ready() {
		t.Fatal("Ready after SELECT_PROTOCOL_ACK(0) = false, want true: no E2EE will ever be established")
	}

	// State().Ready keeps its meaning: frames are not end-to-end encrypted.
	if s.State().Ready {
		t.Error("State().Ready = true on a transport-only channel; frames are not end-to-end encrypted")
	}

	frame := []byte{0xF8, 0xFF, 0xFE}
	out := make([]byte, s.MaxEncryptedFrameSize(len(frame)))

	n, err := s.Encrypt(1234, frame, out)
	if err != nil || !bytes.Equal(out[:n], frame) {
		t.Errorf("Encrypt on a transport-only channel = (%x, %v), want the frame passed through", out[:n], err)
	}
}

// A downgrade is announced at prepare and takes effect at execute, which is
// when the send ratchet is cleared.
func TestReady_DowngradeTakesEffectOnExecute(t *testing.T) {
	s := New("123456789", &kpCapturingCallbacks{})
	s.OnSelectProtocolAck(1)
	activateTestEpoch(t, s)

	s.OnDavePrepareTransition(5, 0)

	if !s.Ready() {
		t.Fatal("Ready during a prepared downgrade = false; the epoch is still encrypting")
	}

	s.OnDaveExecuteTransition(5)

	if !s.Ready() {
		t.Fatal("Ready after an executed downgrade = false, want true: the channel is transport-only now")
	}
}

// An upgrade from version 0 expects E2EE once it executes, so Ready waits for
// the epoch from then on, as it does after SELECT_PROTOCOL_ACK(1).
func TestReady_UpgradeFromVersionZeroWaitsForTheEpoch(t *testing.T) {
	s := New("123456789", &kpCapturingCallbacks{})
	s.OnSelectProtocolAck(0)

	s.OnDavePrepareTransition(6, 1)

	if !s.Ready() {
		t.Fatal("Ready during a prepared upgrade = false; the channel is still transport-only until it executes")
	}

	s.OnDaveExecuteTransition(6)

	if s.Ready() {
		t.Fatal("Ready after an executed upgrade with no epoch = true, want false: E2EE is now expected")
	}
}
