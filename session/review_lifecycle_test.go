package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
)

// R-1. Correct: EpochAuthenticatorCode returns ErrNoActiveEpoch while no
// epoch is active, as its doc says. Triggers: a locally created group never
// activated; a Welcome pending at transition 5.
func TestReview_R1_EpochAuthenticatorCodeMustRequireActiveEpoch(t *testing.T) {
	t.Run("local group, nothing activated", func(t *testing.T) {
		s, _ := reviewSession(t, &reviewCallbacks{})
		if s.Ready() || s.State().EpochID != 0 {
			t.Fatalf("SETUP: an epoch is active: %+v", s.State())
		}
		if code, err := s.EpochAuthenticatorCode(context.Background()); !errors.Is(err, ErrNoActiveEpoch) {
			t.Errorf("R-1: EpochAuthenticatorCode returned %q, err=%v with no active epoch (Ready=false); want ErrNoActiveEpoch", code, err)
		}
	})
	t.Run("Welcome pending, not executed", func(t *testing.T) {
		s, _, _ := reviewTwoMember(t, 5)
		if s.Ready() {
			t.Fatal("SETUP: pending Welcome already active")
		}
		if code, err := s.EpochAuthenticatorCode(context.Background()); !errors.Is(err, ErrNoActiveEpoch) {
			t.Errorf("R-1: EpochAuthenticatorCode returned %q, err=%v for a Welcome not yet executed (Ready=false); want ErrNoActiveEpoch", code, err)
		}
	})
}

// R-2. Correct: State().DegradedSince is set when an established session
// loses its epoch, as the State and WaitReady docs say. Trigger: prepare_epoch(1).
func TestReview_R2_DegradedSinceMustBeSetOnEpochReset(t *testing.T) {
	s := reviewSoleMember(t)
	s.OnDavePrepareEpoch(1, 1)
	st := s.State()
	if st.Ready {
		t.Fatalf("SETUP: still ready after prepare_epoch(1): %+v", st)
	}
	if st.DegradedSince.IsZero() {
		t.Errorf("R-2: State() after an established session's prepare_epoch(1) is %+v: DegradedSince is zero; want the time the epoch was lost", st)
	}
}

// R-3. Correct: the session never creates an MLS group with group ID
// 0x0000000000000000. Trigger: SetChannelID arrives after the external sender
// package, an ordering nothing documents.
func TestReview_R3_GroupIDMustNotBeZeroWhenChannelIDArrivesLate(t *testing.T) {
	s := New(reviewBot, &reviewCallbacks{})
	s.OnSelectProtocolAck(1)
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))
	s.SetChannelID(reviewChannel)
	s.OnDavePrepareTransition(0, 1)

	s.mu.RLock()
	gid := append([]byte(nil), s.groupID...)
	s.mu.RUnlock()
	if bytes.Equal(gid, make([]byte, 8)) {
		t.Errorf("R-3: MLS group created with group ID %x on channel %d (%x); want the channel ID, or no group until it is known",
			gid, reviewChannel, reviewChannelGroupID())
	}
}

// R-4. Correct: WaitShutdown does not report shutdown while a watchdog
// spawned before Close is still running. Trigger: a recovery watchdog whose
// timeout has fired is blocked on the session lock the test holds, so it
// cannot exit; WaitShutdown is given 200 ms.
func TestReview_R4_WaitShutdownMustWaitForWatchdogs(t *testing.T) {
	markers := []string{"(*Session).watchRecoveryLocked.func1", "sync.(*RWMutex).Lock"}
	before := goroutinesIn(markers...)

	s := New(reviewBot, &reviewCallbacks{}, WithRecoveryTimeout(time.Millisecond))
	s.mu.Lock()
	s.watchRecoveryLocked()
	deadline := time.Now().Add(5 * time.Second)
	for goroutinesIn(markers...) == before {
		if time.Now().After(deadline) {
			s.mu.Unlock()
			t.Fatal("SETUP: watchdog never reached the session lock")
		}
		time.Sleep(time.Millisecond)
	}

	_ = s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	err := s.WaitShutdown(ctx)
	cancel()
	alive := goroutinesIn(markers...) > before
	s.mu.Unlock()

	if err == nil && alive {
		t.Error("R-4: WaitShutdown returned nil while the recovery watchdog was still running (blocked on the session lock); want it to wait, or return ctx.Err()")
	}
}

type reviewFailingKPCallbacks struct {
	reviewCallbacks
	failed bool
}

func (c *reviewFailingKPCallbacks) SendMLSKeyPackage(kp []byte) error {
	if !c.failed {
		c.failed = true

		return errors.New("websocket: close sent")
	}

	return c.reviewCallbacks.SendMLSKeyPackage(kp)
}

// R-5. Correct: a key package that failed to send for a non-transient reason
// is not treated as delivered. Trigger: the first SendMLSKeyPackage fails with
// a non-"shard is not ready" error; the gateway then sends the external sender.
func TestReview_R5_FailedKeyPackageSendMustNotStayPending(t *testing.T) {
	cb := &reviewFailingKPCallbacks{}
	s := New(reviewBot, cb)
	s.SetChannelID(reviewChannel)
	s.OnSelectProtocolAck(1)
	if !cb.failed {
		t.Fatal("SETUP: key package send was not attempted")
	}
	s.OnDaveMLSExternalSenderPackage(buildExternalSenderPackage(t))

	s.mu.RLock()
	gid := append([]byte(nil), s.groupID...)
	s.mu.RUnlock()
	if len(cb.keyPackages) == 0 && len(gid) > 0 {
		t.Errorf("R-5: no key package ever reached the gateway, yet the session built MLS group %x from the undelivered one; want it re-sent, or not kept as pending", gid)
	}
}

// R-6. Correct: a pending epoch that came from a Welcome is not rolled back as
// if it were our own lost commit. Trigger: Welcome at transition 5 (pending),
// then the peer's commit at transition 6. Asserts only on the rollback error,
// so it is independent of R-10.
func TestReview_R6_PendingWelcomeEpochMustNotTakeCommitRollbackPath(t *testing.T) {
	logs := &syncBuffer{}
	s, peer, cb := reviewTwoMember(t, 5, WithLogger(reviewDebugLogger(logs)))
	if s.Ready() {
		t.Fatal("SETUP: Welcome activated before execute_transition")
	}

	s.OnDaveMLSPrepareCommitTransition(6, peer.emptyCommit(t))

	if strings.Contains(logs.String(), ErrNoPreCommitState.Error()) {
		t.Errorf("R-6: a commit arriving over a pending Welcome epoch took the lost-commit rollback, failed with %q, and sent invalid_commit_welcome %v; want no rollback attempted",
			ErrNoPreCommitState, cb.invalidCommitIDs())
	}
}

// R-8. Correct: a passthrough copy into a too-short output buffer reports an
// error rather than returning a truncated frame. Trigger: protocol version 0
// (legitimate passthrough, so this is independent of C-6), 40-byte frame,
// 10-byte buffer.
func TestReview_R8_PassthroughMustNotTruncateSilently(t *testing.T) {
	frameData := bytes.Repeat([]byte{0x33}, 40)
	if frame.LooksLikeDAVEFrame(frameData) {
		t.Fatal("SETUP: frame looks like DAVE")
	}
	s := New(reviewBot, &reviewCallbacks{})
	s.AssignSsrcToCodec(reviewSSRC, godave.CodecOpus)
	s.OnSelectProtocolAck(0)

	t.Run("Encrypt", func(t *testing.T) {
		out := make([]byte, 10)
		if n, err := s.Encrypt(reviewSSRC, frameData, out); err == nil && n < len(frameData) {
			t.Errorf("R-8: Encrypt passthrough returned n=%d of a %d-byte frame with nil error; want an error", n, len(frameData))
		}
	})
	t.Run("Decrypt", func(t *testing.T) {
		out := make([]byte, 10)
		if n, err := s.Decrypt(reviewPeer, frameData, out); err == nil && n < len(frameData) {
			t.Errorf("R-8: Decrypt passthrough returned n=%d of a %d-byte frame with nil error; want an error", n, len(frameData))
		}
	})
}

// R-9. Correct: Encrypt on an SSRC with no codec assigned encrypts the whole
// frame as an unknown codec, as libdave does. Trigger: SSRC 99, never assigned.
func TestReview_R9_UnassignedSSRCMustEncryptAsUnknownCodec(t *testing.T) {
	s := reviewSoleMember(t)
	p := []byte("audio on an unassigned ssrc")
	out := make([]byte, s.MaxEncryptedFrameSize(len(p)))
	n, err := s.Encrypt(99, p, out)
	if err != nil {
		t.Errorf("R-9: Encrypt on unassigned SSRC 99 failed: %v; want the frame encrypted as an unknown codec", err)

		return
	}
	if !frame.LooksLikeDAVEFrame(out[:n]) {
		t.Errorf("R-9: Encrypt on unassigned SSRC 99 returned a non-DAVE frame %x", out[:n])
	}
}

// R-10. Correct: a commit that carries no proposals is refused, as libdave
// does. Trigger: the peer commits with nothing pending.
func TestReview_R10_CommitWithNoProposalsMustBeRefused(t *testing.T) {
	s, peer, _ := reviewTwoMember(t, 0)
	commit := peer.emptyCommit(t)
	msg, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		t.Fatalf("SETUP: parse commit: %v", err)
	}
	pub, _ := msg.AsPublic()
	data, _ := pub.Content.CommitData()
	c, err := group.UnmarshalCommit(data)
	if err != nil || len(c.Proposals) != 0 {
		t.Fatalf("SETUP: commit carries %d proposals (err %v); want 0", len(c.Proposals), err)
	}
	before := s.State().EpochID

	s.OnDaveMLSPrepareCommitTransition(7, commit)
	s.OnDaveExecuteTransition(7)

	if st := s.Stats(); st.CommitsProcessed != 0 {
		t.Errorf("R-10: a commit with no proposals was processed (CommitsProcessed=%d, epoch %d -> %d); want it refused",
			st.CommitsProcessed, before, s.State().EpochID)
	}
}

// R-15. Correct: the package's tests run with the production retry back-off,
// or restore it after changing it. retry_test.go's init() sets retryDelay to 0
// for every test in the package and never restores it, so no existing test
// can observe back-off behaviour such as C-5.
func TestReview_R15_RetryDelayMustNotBeZeroedForWholePackage(t *testing.T) {
	const production = 500 * time.Millisecond
	if retryDelay != production {
		t.Errorf("R-15: retryDelay is %v for every test in package session (production %v): a package init() zeroed it", retryDelay, production)
	}
}
