package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/dave-go/mediakeys"
)

type testCallbacks struct{}

func (testCallbacks) SendMLSKeyPackage([]byte) error        { return nil }
func (testCallbacks) SendMLSCommitWelcome([]byte) error     { return nil }
func (testCallbacks) SendReadyForTransition(uint16) error   { return nil }
func (testCallbacks) SendInvalidCommitWelcome(uint16) error { return nil }

// TestCreateFunc verifies the create func hands the integrator the concrete
// *Session via WithSessionHook, so they don't have to type-assert the
// godave.Session to observe or close it.
func TestCreateFunc(t *testing.T) {
	cb := testCallbacks{}
	var got *Session

	createFunc := CreateFunc(WithSessionHook(func(s *Session) {
		got = s
	}))

	s := createFunc(nil, "123456789", cb)
	if s == nil {
		t.Fatal("CreateFunc create func returned nil")
	}
	if got == nil {
		t.Fatal("session hook was not invoked")
	}
	if got.State().Ready {
		t.Fatal("a fresh session should not report E2EE-ready")
	}

	// No options at all must not panic, and nil options must be skipped.
	if CreateFunc()(nil, "123456789", cb) == nil {
		t.Fatal("CreateFunc() create func returned nil")
	}
	if New("123456789", cb, nil, WithSessionHook(nil)) == nil {
		t.Fatal("New with nil option returned nil")
	}
}

func TestNewSession(t *testing.T) {
	s := New("test_user", testCallbacks{})
	if s == nil {
		t.Fatal("NewSession returned nil")
	}
	if s.MaxSupportedProtocolVersion() != 1 {
		t.Fatalf("expected protocol version 1, got %d", s.MaxSupportedProtocolVersion())
	}
}

func TestMaxEncryptedFrameSize(t *testing.T) {
	s := New("test_user", testCallbacks{})
	got := s.MaxEncryptedFrameSize(100)
	if got != 164 {
		t.Fatalf("expected 164, got %d", got)
	}
}

func TestMaxDecryptedFrameSize(t *testing.T) {
	s := New("test_user", testCallbacks{})
	got := s.MaxDecryptedFrameSize("user1", 200)
	if got != 200 {
		t.Fatalf("expected 200, got %d", got)
	}
}

func TestAssignSsrcToCodec(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.AssignSsrcToCodec(12345, godave.CodecOpus)

	sess := s
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if kind, ok := sess.ssrcCodecs[12345]; !ok || kind != 1 {
		t.Fatalf("expected CodecOpus for SSRC 12345")
	}
}

func TestAddRemoveUser(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.AddUser("user1")
	s.AddUser("user2")

	sess := s
	sess.mu.RLock()
	if len(sess.users) != 2 {
		t.Fatalf("expected 2 users, got %d", len(sess.users))
	}
	sess.mu.RUnlock()

	s.RemoveUser("user1")
	sess.mu.RLock()
	if len(sess.users) != 1 {
		t.Fatalf("expected 1 user after remove, got %d", len(sess.users))
	}
	sess.mu.RUnlock()
}

func TestSetChannelID(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.SetChannelID(42)

	sess := s
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.channelID != 42 {
		t.Fatalf("expected channelID 42, got %d", sess.channelID)
	}
}

func TestOnSelectProtocolAck(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.OnSelectProtocolAck(1)

	sess := s
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.protocolVersion != 1 {
		t.Fatalf("expected protocol version 1, got %d", sess.protocolVersion)
	}
}

func TestOnDavePrepareTransition(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.OnDavePrepareTransition(5, 1)

	sess := s
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.pendingTransitionID != 5 {
		t.Fatalf("expected pendingTransitionID 5, got %d", sess.pendingTransitionID)
	}
}

func TestOnDaveExecuteTransitionNoPendingEpoch(t *testing.T) {
	s := New("test_user", testCallbacks{})
	s.OnDavePrepareTransition(5, 1)
	s.OnDaveExecuteTransition(5)

	sess := s
	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.activeTransitionID != 5 {
		t.Fatalf("expected activeTransitionID 5, got %d", sess.activeTransitionID)
	}
	if sess.pendingTransitionID != 0 {
		t.Fatalf("expected pendingTransitionID 0, got %d", sess.pendingTransitionID)
	}
}

func TestOnDaveExecuteTransitionOnlyPreparedID(t *testing.T) {
	const preparedID = 5
	tests := []struct {
		name            string
		protocolVersion uint16
		executeID       uint16
		wantExecuted    bool
	}{
		{"prepared", 1, preparedID, true},
		{"other_id", 1, preparedID + 1, false},
		{"downgrade_prepared", 0, preparedID, true},
		{"downgrade_other_id", 0, preparedID + 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("test_user", testCallbacks{})
			s.OnDavePrepareTransition(preparedID, tt.protocolVersion)
			s.mu.Lock()
			s.pendingEpoch = &epochState{id: 100}
			s.mu.Unlock()

			s.OnDaveExecuteTransition(tt.executeID)

			s.mu.RLock()
			defer s.mu.RUnlock()
			if executed := s.pendingEpoch == nil; executed != tt.wantExecuted {
				t.Errorf("executed=%v, want %v", executed, tt.wantExecuted)
			}
			if recorded := s.activeTransitionID == tt.executeID; recorded != tt.wantExecuted {
				t.Errorf("activeTransitionID=%d, want executed=%v", s.activeTransitionID, tt.wantExecuted)
			}
			if wantTransportOnly := tt.wantExecuted && tt.protocolVersion == 0; s.transportOnly != wantTransportOnly {
				t.Errorf("transportOnly=%v, want %v", s.transportOnly, wantTransportOnly)
			}
		})
	}
}

func TestDecryptRetainedEpochExpiry(t *testing.T) {
	const retainedEpochID = 1
	tests := []struct {
		name      string
		expiresIn time.Duration
		wantErr   bool
	}{
		{"within_retention", epochRetention, false},
		{"after_retention", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("test_user", testCallbacks{})
			ratchet := makeTestRatchet(t)
			s.mu.Lock()
			s.protocolVersion = uint16(s.MaxSupportedProtocolVersion())
			s.activeEpoch = &epochState{id: retainedEpochID + 1, senders: map[godave.UserID]*senderState{}}
			s.retainedEpoch = []*epochState{{
				id:        retainedEpochID,
				expiresAt: time.Now().Add(tt.expiresIn),
				senders: map[godave.UserID]*senderState{
					"peer": {ratchet: ratchet, expander: mediakeys.NewNonceExpander()},
				},
			}}
			s.mu.Unlock()

			key, err := ratchet.GetKey(ratchet.CurrentGeneration())
			if err != nil {
				t.Fatalf("GetKey: %v", err)
			}
			encrypted, err := frame.Encrypt(frame.EncryptParams{
				Plaintext: []byte("old epoch audio"),
				Key:       key,
			})
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			_, err = s.Decrypt("peer", encrypted, make([]byte, len(encrypted)))
			if (err != nil) != tt.wantErr {
				t.Errorf("got err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestPassthroughShortBuffer(t *testing.T) {
	frameData := bytes.Repeat([]byte{0x33}, 40)
	tests := []struct {
		name string
		run  func(s *Session, out []byte) (int, error)
	}{
		{"Encrypt", func(s *Session, out []byte) (int, error) { return s.Encrypt(1, frameData, out) }},
		{"Decrypt", func(s *Session, out []byte) (int, error) { return s.Decrypt("peer", frameData, out) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := New("test_user", testCallbacks{})
			s.OnSelectProtocolAck(0)

			if _, err := tt.run(s, make([]byte, len(frameData)-1)); !errors.Is(err, frame.ErrBufferTooSmall) {
				t.Errorf("got err=%v, want %v", err, frame.ErrBufferTooSmall)
			}
			if n, err := tt.run(s, make([]byte, len(frameData))); err != nil || n != len(frameData) {
				t.Errorf("full-length buffer: n=%d, err=%v", n, err)
			}
		})
	}
}

func TestDecryptShortBufferKeepsFrame(t *testing.T) {
	s := New("test_user", testCallbacks{})
	ratchet := makeTestRatchet(t)
	s.mu.Lock()
	s.protocolVersion = 1
	s.activeEpoch = &epochState{
		id: 1,
		senders: map[godave.UserID]*senderState{
			"peer": {ratchet: ratchet, expander: mediakeys.NewNonceExpander()},
		},
	}
	s.mu.Unlock()

	key, err := ratchet.GetKey(0)
	if err != nil {
		t.Fatalf("GetKey(0): %v", err)
	}
	plaintext := []byte("opus frame payload")
	encrypted, err := frame.Encrypt(frame.EncryptParams{Plaintext: plaintext, Key: key})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := s.Decrypt("peer", encrypted, make([]byte, len(plaintext)-1)); !errors.Is(err, frame.ErrBufferTooSmall) {
		t.Errorf("got err=%v, want %v", err, frame.ErrBufferTooSmall)
	}
	// The short buffer must not have used up the frame's nonce.
	out := make([]byte, len(plaintext))
	if n, err := s.Decrypt("peer", encrypted, out); err != nil || !bytes.Equal(out[:n], plaintext) {
		t.Errorf("retry with a full-length buffer: n=%d, err=%v", n, err)
	}
}

func TestOnDavePrepareEpochReset(t *testing.T) {
	s := New("test_user", testCallbacks{})
	sess := s

	sess.activeEpoch = &epochState{id: 99}
	sess.pendingEpoch = &epochState{id: 100}

	s.OnDavePrepareEpoch(1, 1)

	sess.mu.RLock()
	defer sess.mu.RUnlock()

	if sess.activeEpoch != nil {
		t.Fatal("expected activeEpoch nil after epoch=1")
	}
	if sess.pendingEpoch != nil {
		t.Fatal("expected pendingEpoch nil after epoch=1")
	}
}

// TestEncryptNoActiveEpochPassesThrough verifies that with no active epoch the
// frame is forwarded unmodified (passthrough) instead of failing, so the audio
// stream keeps advancing when the bot is alone or mid-transition.
func TestEncryptNoActiveEpochPassesThrough(t *testing.T) {
	s := New("test_user", testCallbacks{})
	sess := s

	plaintext := []byte{0x01, 0x02, 0x03, 0x04}
	out := make([]byte, 256)
	n, err := sess.Encrypt(12345, plaintext, out)
	if err != nil {
		t.Fatalf("expected passthrough, got error: %v", err)
	}
	if n != len(plaintext) {
		t.Fatalf("passthrough wrote %d bytes, want %d", n, len(plaintext))
	}
	if !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("passthrough altered the frame: got %x, want %x", out[:n], plaintext)
	}
	if got := sess.Stats().PassthroughFrames; got != 1 {
		t.Fatalf("PassthroughFrames = %d, want 1", got)
	}
	if sess.State().Ready {
		t.Fatal("State().Ready should be false while in passthrough")
	}
}

func TestWaitReadyContextCanceled(t *testing.T) {
	s := New("test_user", testCallbacks{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := s.WaitReady(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestWaitReadyAlreadyReady(t *testing.T) {
	sess := New("test_user", testCallbacks{})

	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	d, err := sess.WaitReady(ctx)
	if err != nil {
		t.Fatalf("WaitReady returned unexpected error: %v", err)
	}
	if d > time.Millisecond {
		t.Fatalf("expected near-zero duration when already ready, got %v", d)
	}
}

func TestWaitReadySignaled(t *testing.T) {
	sess := New("test_user", testCallbacks{})

	ready := make(chan time.Duration, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, _ := sess.WaitReady(ctx)
		ready <- d
	}()

	time.Sleep(10 * time.Millisecond)

	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.signalEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case d := <-ready:
		if d <= 0 {
			t.Fatalf("expected positive duration, got %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReady did not return after epoch was signaled")
	}
}

func TestWaitReadyEpochReset(t *testing.T) {
	sess := New("test_user", testCallbacks{})

	ready := make(chan time.Duration, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		d, _ := sess.WaitReady(ctx)
		ready <- d
	}()

	time.Sleep(10 * time.Millisecond)

	// First: simulate a reset (PrepareEpoch for a new epoch) — goroutine must re-wait.
	sess.mu.Lock()
	sess.resetEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case <-ready:
		t.Fatal("WaitReady returned after reset but before ready")
	case <-time.After(20 * time.Millisecond):
		// good: still waiting
	}

	// Now signal ready.
	sess.mu.Lock()
	sess.activeEpoch = &epochState{id: 2, senders: make(map[godave.UserID]*senderState)}
	var ratchet mediakeys.KeyRatchet
	sess.sendRatchet = &ratchet
	sess.signalEpochReadyLocked()
	sess.mu.Unlock()

	select {
	case d := <-ready:
		if d <= 0 {
			t.Fatalf("expected positive duration after reset+signal, got %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("WaitReady did not return after reset then signal")
	}
}

func TestDecryptNoActiveEpoch(t *testing.T) {
	s := New("test_user", testCallbacks{})

	// Use a frame that passes LooksLikeDAVEFrame so the epoch check is reached.
	// 11 bytes minimum with 0xFA 0xFA magic marker at the end.
	fakeDAVEFrame := make([]byte, 11)
	fakeDAVEFrame[9] = 0xFA
	fakeDAVEFrame[10] = 0xFA
	_, err := s.Decrypt("user1", fakeDAVEFrame, make([]byte, 256))
	if err == nil {
		t.Fatal("expected error when decrypting with no epoch")
	}
}

// TestDecrypt_PassthroughGuardWithActiveEpoch covers the E2EE passthrough
// restriction: when an active epoch is in place, a non-DAVE frame must be
// rejected unless it is exactly the 3-byte silence packet (0xF8FFFE) the
// spec allows through (protocol.md:107-111, 633-641). Without an active
// epoch (v0 / transition / fresh session), passthrough stays permissive.
func TestDecrypt_PassthroughGuardWithActiveEpoch(t *testing.T) {
	t.Run("rejects non-dave non-silence under E2EE", func(t *testing.T) {
		sess := New("test_user", testCallbacks{})

		sess.mu.Lock()
		sess.protocolVersion = 1
		sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
		sess.mu.Unlock()

		// Arbitrary non-DAVE plaintext frame, not the silence packet.
		bad := []byte{0x01, 0x02, 0x03, 0x04}
		_, err := sess.Decrypt("user1", bad, make([]byte, 64))
		if err == nil {
			t.Fatal("expected ErrDecryptionFailed for plaintext injection under E2EE")
		}
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("rejects non-dave frame of different size under E2EE", func(t *testing.T) {
		sess := New("test_user", testCallbacks{})

		sess.mu.Lock()
		sess.protocolVersion = 1
		sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
		sess.mu.Unlock()

		// A 10-byte frame that is neither a DAVE frame (no 0xFA 0xFA magic)
		// nor a 3-byte silence packet.
		bad := make([]byte, 10)
		bad[0] = 0xAB
		_, err := sess.Decrypt("user1", bad, make([]byte, 64))
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("expected ErrDecryptionFailed, got %v", err)
		}
	})

	t.Run("allows silence packet under E2EE", func(t *testing.T) {
		sess := New("test_user", testCallbacks{})

		sess.mu.Lock()
		sess.protocolVersion = 1
		sess.activeEpoch = &epochState{id: 1, senders: make(map[godave.UserID]*senderState)}
		sess.mu.Unlock()

		silence := []byte{0xF8, 0xFF, 0xFE}
		out := make([]byte, 64)
		n, err := sess.Decrypt("user1", silence, out)
		if err != nil {
			t.Fatalf("silence packet should pass through under E2EE, got error: %v", err)
		}
		if n != len(silence) {
			t.Fatalf("silence passthrough wrote %d bytes, want %d", n, len(silence))
		}
		if !bytes.Equal(out[:n], silence) {
			t.Fatalf("silence passthrough altered the frame: got %x, want %x", out[:n], silence)
		}
	})

	t.Run("allows arbitrary non-dave frame when no active epoch", func(t *testing.T) {
		sess := New("test_user", testCallbacks{})

		// No active epoch: passthrough remains permissive (v0 / transition /
		// fresh session), regardless of the frame content.
		plaintext := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
		out := make([]byte, 64)
		n, err := sess.Decrypt("user1", plaintext, out)
		if err != nil {
			t.Fatalf("expected passthrough without active epoch, got error: %v", err)
		}
		if n != len(plaintext) {
			t.Fatalf("passthrough wrote %d bytes, want %d", n, len(plaintext))
		}
		if !bytes.Equal(out[:n], plaintext) {
			t.Fatalf("passthrough altered the frame: got %x, want %x", out[:n], plaintext)
		}
	})
}

func TestDecrypt_ReplayRejected(t *testing.T) {
	sess := New("test_user", testCallbacks{})

	// Build a sole-member session so we have real key material.
	sess.mu.Lock()
	// Minimal sole-member setup: set channel and protocol version.
	sess.channelID = 987654321
	sess.protocolVersion = 1
	// Create a fake epoch with the bot's own UserID as a sender.
	// We need a real ratchet key to encrypt/decrypt.
	ratchet, err := mediakeys.NewKeyRatchet(bytes.Repeat([]byte{0xAA}, 16))
	if err != nil {
		sess.mu.Unlock()
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	sess.activeEpoch = &epochState{
		id:      1,
		groupID: []byte("test-group"),
		senders: map[godave.UserID]*senderState{
			"test_user": {
				ratchet:  ratchet,
				expander: mediakeys.NewNonceExpander(),
				replay:   antiReplayWindow{},
			},
		},
	}
	sess.mu.Unlock()

	// Get the generation-0 key and encrypt a frame with it.
	key, err := ratchet.GetKey(0)
	if err != nil {
		t.Fatalf("GetKey(0): %v", err)
	}

	plaintext := []byte{0x10, 0x20, 0x30, 0x40, 0x50}
	encrypted, err := frame.Encrypt(frame.EncryptParams{
		Plaintext:      plaintext,
		Key:            key,
		TruncatedNonce: 0, // nonce 0 → generation 0
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// First decrypt must succeed.
	out := make([]byte, 256)
	n, err := sess.Decrypt("test_user", encrypted, out)
	if err != nil {
		t.Fatalf("first decrypt: %v", err)
	}
	if !bytes.Equal(out[:n], plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", out[:n], plaintext)
	}

	// Second decrypt of the same frame must be rejected as replay.
	_, err = sess.Decrypt("test_user", encrypted, out)
	if err == nil {
		t.Fatal("expected replay rejection on second decrypt")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("expected ErrDecryptionFailed, got %v", err)
	}

	// Stats must reflect the rejected replay.
	if got := sess.Stats().RejectedReplayFrames; got != 1 {
		t.Fatalf("RejectedReplayFrames: got %d want 1", got)
	}
}

func TestDecrypt_OutOfOrderAccepted(t *testing.T) {
	sess := New("test_user", testCallbacks{})

	sess.mu.Lock()
	sess.channelID = 987654321
	sess.protocolVersion = 1
	ratchet, err := mediakeys.NewKeyRatchet(bytes.Repeat([]byte{0xBB}, 16))
	if err != nil {
		sess.mu.Unlock()
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	sess.activeEpoch = &epochState{
		id:      1,
		groupID: []byte("test-group"),
		senders: map[godave.UserID]*senderState{
			"test_user": {
				ratchet:  ratchet,
				expander: mediakeys.NewNonceExpander(),
				replay:   antiReplayWindow{},
			},
		},
	}
	sess.mu.Unlock()

	// Encrypt frames with nonces 0, 1, 2.
	plaintext := []byte{0xAA, 0xBB, 0xCC}
	var frames [3][]byte
	for i := range 3 {
		key, err := ratchet.GetKey(0) // all nonce < 2^24 → generation 0
		if err != nil {
			t.Fatalf("GetKey(0) for nonce %d: %v", i, err)
		}
		frames[i], err = frame.Encrypt(frame.EncryptParams{
			Plaintext:      plaintext,
			Key:            key,
			TruncatedNonce: uint32(i),
		})
		if err != nil {
			t.Fatalf("Encrypt nonce %d: %v", i, err)
		}
	}

	// Decrypt out of order: 2, 0, 1 — all must succeed.
	order := []int{2, 0, 1}
	out := make([]byte, 256)
	for _, idx := range order {
		n, err := sess.Decrypt("test_user", frames[idx], out)
		if err != nil {
			t.Fatalf("decrypt frame %d (out of order): %v", idx, err)
		}
		if !bytes.Equal(out[:n], plaintext) {
			t.Fatalf("frame %d: plaintext mismatch", idx)
		}
	}
}
