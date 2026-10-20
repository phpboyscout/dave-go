package session

import (
	"errors"
	"testing"
	"time"
)

func activeSoleMemberSessionWithGrace(t *testing.T, grace time.Duration) *Session {
	t.Helper()
	s := New("123456789", testCallbacks{})
	closeAtCleanup(t, s)
	s.plaintextGrace = grace
	s.SetChannelID(987654321)
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.OnDavePrepareTransition(0, 1)
	if !s.State().Ready {
		t.Fatal("sole-member epoch not active")
	}

	return s
}

func decryptPlaintext(s *Session) error {
	_, err := s.Decrypt("peer", []byte{0x01, 0x02, 0x03, 0x04}, make([]byte, 64))

	return err
}

func TestDecrypt_PlaintextAcceptedDuringHandshake(t *testing.T) {
	s := New("123456789", testCallbacks{})
	closeAtCleanup(t, s)
	s.OnSelectProtocolAck(1)

	if err := decryptPlaintext(s); err != nil {
		t.Fatalf("plaintext before the first epoch: %v", err)
	}
}

func TestDecrypt_PlaintextAcceptedForGraceAfterFirstEpoch(t *testing.T) {
	const grace = 50 * time.Millisecond
	s := activeSoleMemberSessionWithGrace(t, grace)

	if err := decryptPlaintext(s); err != nil {
		t.Fatalf("plaintext within the grace: %v", err)
	}
	time.Sleep(2 * grace)
	if err := decryptPlaintext(s); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("plaintext after the grace: err = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecrypt_PlaintextStaysRejectedAfterReset(t *testing.T) {
	tests := []struct {
		name  string
		reset func(s *Session)
	}{
		{name: "prepare_epoch(1)", reset: func(s *Session) { s.OnDavePrepareEpoch(1, 1) }},
		{name: "select_protocol_ack(1)", reset: func(s *Session) { s.OnSelectProtocolAck(1) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := activeSoleMemberSessionWithGrace(t, 0)
			tt.reset(s)
			if s.State().Ready {
				t.Fatal("reset left the epoch active")
			}

			if err := decryptPlaintext(s); !errors.Is(err, ErrDecryptionFailed) {
				t.Fatalf("plaintext after the reset: err = %v, want ErrDecryptionFailed", err)
			}
		})
	}
}

func TestDecrypt_NoPlaintextGraceAfterReset(t *testing.T) {
	const grace = 50 * time.Millisecond
	s := activeSoleMemberSessionWithGrace(t, grace)
	time.Sleep(2 * grace)
	s.OnDavePrepareEpoch(1, 1)
	s.OnDavePrepareTransition(0, 1)
	if !s.State().Ready {
		t.Fatal("sole-member epoch not active after the reset")
	}

	if err := decryptPlaintext(s); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("plaintext after the new epoch: err = %v, want ErrDecryptionFailed", err)
	}
}

func TestDecrypt_PlaintextReopenedByProtocolVersion0(t *testing.T) {
	tests := []struct {
		name      string
		downgrade func(t *testing.T, s *Session)
	}{
		{name: "transition", downgrade: func(t *testing.T, s *Session) {
			t.Helper()
			s.OnDavePrepareTransition(5, 0)
			if err := decryptPlaintext(s); err != nil {
				t.Fatalf("plaintext once the downgrade is prepared: %v", err)
			}
			s.OnDaveExecuteTransition(5)
		}},
		{name: "select_protocol_ack(0)", downgrade: func(_ *testing.T, s *Session) { s.OnSelectProtocolAck(0) }},
		{name: "prepare_epoch(1) at version 0", downgrade: func(_ *testing.T, s *Session) { s.OnDavePrepareEpoch(1, 0) }},
		{name: "sole-member epoch at version 0", downgrade: func(_ *testing.T, s *Session) {
			s.OnDavePrepareEpoch(1, 0)
			s.OnDavePrepareTransition(0, 0)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := activeSoleMemberSessionWithGrace(t, 0)
			tt.downgrade(t, s)
			if err := decryptPlaintext(s); err != nil {
				t.Fatalf("plaintext at version 0: %v", err)
			}

			s.OnSelectProtocolAck(1)
			if err := decryptPlaintext(s); err != nil {
				t.Fatalf("plaintext during the handshake after an upgrade: %v", err)
			}
		})
	}
}
