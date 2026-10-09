package session

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/thomas-vilte/dave-go/mediakeys"
)

// TestState_ProtocolVersionExposed covers that the internal protocolVersion
// is reflected in State().ProtocolVersion across the three opcodes that
// update it (SELECT_PROTOCOL_ACK, PREPARE_EPOCH, PREPARE_TRANSITION).
func TestState_ProtocolVersionExposed(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	// Before any opcode: v0, Ready false.
	st := s.State()
	if st.ProtocolVersion != 0 {
		t.Fatalf("ProtocolVersion pre-ack = %d, want 0", st.ProtocolVersion)
	}
	if st.Ready {
		t.Fatal("Ready pre-ack = true, want false")
	}

	// OnSelectProtocolAck(v>0) updates it.
	s.OnSelectProtocolAck(1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnSelectProtocolAck = %d, want 1", got)
	}

	// OnDavePrepareEpoch with epoch==1 resets state but must still report >0.
	s.OnDavePrepareEpoch(1, 1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnDavePrepareEpoch = %d, want 1", got)
	}

	// OnDavePrepareTransition also updates it.
	s.OnDavePrepareTransition(5, 1)
	if got := s.State().ProtocolVersion; got != 1 {
		t.Fatalf("ProtocolVersion after OnDavePrepareTransition = %d, want 1", got)
	}
}

// TestState_ReadyFalse_DistinguishesV0_FromHandshake verifies that an
// integrator with access to State can tell apart the two cases where
// Ready()==false: stable v0 (ProtocolVersion==0) and a transient handshake
// (ProtocolVersion>0). The recommended pattern is to gate on
// (Ready || ProtocolVersion == 0): passthrough forever on v0, hold during
// the handshake.
func TestState_ReadyFalse_DistinguishesV0_FromHandshake(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	// Stable v0: Ready=false && ProtocolVersion=0 → "no E2EE forever".
	st := s.State()
	if st.Ready || st.ProtocolVersion != 0 {
		t.Fatalf("expected v0: Ready=%v ProtocolVersion=%d", st.Ready, st.ProtocolVersion)
	}
	if !st.Ready && st.ProtocolVersion != 0 {
		t.Fatal("v0 state was not recognized as stable no-E2EE")
	}

	// Transient handshake: OnSelectProtocolAck(1) leaves ProtocolVersion=1,
	// still !Ready.
	s.OnSelectProtocolAck(1)
	st = s.State()
	if st.Ready {
		t.Fatal("Ready should be false during a transient handshake")
	}
	if st.ProtocolVersion == 0 {
		t.Fatal("ProtocolVersion==0 during transient handshake, want >0")
	}
	// Integrator logic: hold frames in this case.
	if st.ProtocolVersion == 0 || st.Ready {
		t.Fatal("transient handshake was not identified")
	}

	// Activate an epoch (sole-member reset) → Ready=true.
	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	s.mu.Lock()
	// Minimal path to reach Ready without driving the full MLS flow: sole-member.
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
	st = s.State()
	if !st.Ready {
		t.Fatal("Ready=false after setting sendRatchet+activeEpoch")
	}
}

// TestReady_PatternGateReadyOrV0 covers that the recommended pattern
// (Ready || ProtocolVersion == 0) composes correctly with the State
// snapshot: a bot on v0 can use the pattern without touching internal code
// paths, and a transient handshake doesn't let it proceed by mistake.
func TestReady_PatternGateReadyOrV0(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	// Stable v0: the "proceed" pattern (passthrough forever).
	st := s.State()
	if st.Ready || st.ProtocolVersion != 0 {
		t.Fatal("expected stable v0 at session start")
	}
	proceed := st.Ready || st.ProtocolVersion == 0
	if !proceed {
		t.Fatal("stable v0 should allow proceed via the recommended pattern")
	}

	// Transient handshake: the "hold" pattern.
	s.OnSelectProtocolAck(1)
	st = s.State()
	proceed = st.Ready || st.ProtocolVersion == 0
	if proceed {
		t.Fatal("transient handshake should hold (got proceed=true)")
	}

	// Ready=true: the "proceed" pattern via Ready.
	ratchet, _ := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	s.mu.Lock()
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
	st = s.State()
	proceed = st.Ready || st.ProtocolVersion == 0
	if !proceed {
		t.Fatal("Ready=true should allow proceed")
	}
}

// TestShouldHoldFrames verifies the method encodes the recommended gate
// across the three states: stable v0 (don't hold — passthrough forever),
// transient handshake (hold), and Ready (don't hold).
func TestShouldHoldFrames(t *testing.T) {
	cb := &kpCapturingCallbacks{}
	s := New("123456789", cb)

	// Stable v0: no E2EE coming, never hold.
	if s.ShouldHoldFrames() {
		t.Fatal("ShouldHoldFrames=true on stable v0, want false")
	}

	// Transient handshake: E2EE expected but not established — hold.
	s.OnSelectProtocolAck(1)
	if !s.ShouldHoldFrames() {
		t.Fatal("ShouldHoldFrames=false during handshake, want true")
	}

	// Epoch active: ready to encrypt, don't hold.
	ratchet, err := mediakeys.NewKeyRatchet(make([]byte, mediakeys.BaseSecretLen))
	if err != nil {
		t.Fatalf("NewKeyRatchet: %v", err)
	}
	s.mu.Lock()
	s.sendRatchet = ratchet
	s.activeEpoch = &epochState{id: 4, groupID: []byte("g")}
	s.mu.Unlock()
	if s.ShouldHoldFrames() {
		t.Fatal("ShouldHoldFrames=true while Ready, want false")
	}
}

func TestState_DegradedSinceOnEpochReset(t *testing.T) {
	tests := []struct {
		name            string
		established     bool
		protocolVersion uint16
		wantDegraded    bool
		alreadyDegraded bool
	}{
		{"established_reset", true, 1, true, false},
		{"established_downgrade", true, 0, false, false},
		{"first_epoch", false, 1, false, false},
		{"already_degraded", true, 1, true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var logs bytes.Buffer
			cb := &kpCapturingCallbacks{}
			s := New("123456789", cb, WithLogger(slog.New(slog.NewJSONHandler(&logs, nil))))
			s.SetChannelID(987654321)
			s.OnSelectProtocolAck(1)
			if tt.established {
				s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
				s.OnDavePrepareTransition(0, 1)
				if !s.State().Ready {
					t.Fatal("sole-member epoch not active")
				}
			}

			if tt.alreadyDegraded {
				s.mu.Lock()
				s.markDegradedLocked("earlier fault")
				s.mu.Unlock()
			}
			before := s.State().DegradedSince

			logs.Reset()
			s.OnDavePrepareEpoch(1, tt.protocolVersion)
			if degraded := !s.State().DegradedSince.IsZero(); degraded != tt.wantDegraded {
				t.Fatalf("after prepare_epoch(1, %d): degraded=%v, want %v", tt.protocolVersion, degraded, tt.wantDegraded)
			}
			if !tt.wantDegraded {
				return
			}
			if tt.alreadyDegraded {
				if got := s.State().DegradedSince; !got.Equal(before) || strings.Contains(logs.String(), "entering degraded") {
					t.Errorf("reset while degraded moved DegradedSince %v -> %v or logged again:\n%s", before, got, logs.String())
				}

				return
			}
			if out := logs.String(); !strings.Contains(out, "session entering degraded state") || strings.Contains(out, `"level":"WARN"`) {
				t.Errorf("want the degraded line at Info, not Warn:\n%s", out)
			}

			s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
			s.OnDavePrepareTransition(0, tt.protocolVersion)
			if st := s.State(); !st.Ready || !st.DegradedSince.IsZero() {
				t.Errorf("after the sole-member epoch reactivated: %+v, want Ready with DegradedSince cleared", st)
			}
		})
	}
}
