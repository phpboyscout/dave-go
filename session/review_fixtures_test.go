package session

// Shared fixtures for the review_*_test.go regression tests. They live in
// package session because several findings concern state no public method
// exposes (group ID, MLS store, send TTL), and because the existing fixtures
// they reuse (kpCapturingCallbacks, buildExternalSenderPackage) are unexported.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/disgoorg/godave"
	"github.com/thomas-vilte/dave-go/frame"
	"github.com/thomas-vilte/dave-go/mediakeys"
	"github.com/thomas-vilte/mls-go"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/group"
	memorystore "github.com/thomas-vilte/mls-go/storage/memory"
)

const (
	reviewBot     godave.UserID    = "123456789"
	reviewPeer    godave.UserID    = "987654321"
	reviewPeerID  uint64           = 987654321
	reviewChannel godave.ChannelID = 555000111
	reviewSSRC    uint32           = 42
)

func reviewChannelGroupID() []byte {
	gid := make([]byte, 8)
	binary.BigEndian.PutUint64(gid, uint64(reviewChannel))

	return gid
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.String()
}

func reviewDebugLogger(buf *syncBuffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// reviewCallbacks records what the session sent to the gateway.
type reviewCallbacks struct {
	mu             sync.Mutex
	keyPackages    [][]byte
	invalidCommits []uint16
	readyIDs       []uint16
}

func (c *reviewCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keyPackages = append(c.keyPackages, append([]byte(nil), kp...))

	return nil
}

func (c *reviewCallbacks) SendMLSCommitWelcome([]byte) error { return nil }

func (c *reviewCallbacks) SendReadyForTransition(id uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readyIDs = append(c.readyIDs, id)

	return nil
}

func (c *reviewCallbacks) SendInvalidCommitWelcome(id uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.invalidCommits = append(c.invalidCommits, id)

	return nil
}

func (c *reviewCallbacks) lastKeyPackage() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.keyPackages) == 0 {
		return nil
	}

	return c.keyPackages[len(c.keyPackages)-1]
}

func (c *reviewCallbacks) invalidCommitIDs() []uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()

	return append([]uint16(nil), c.invalidCommits...)
}

// reviewPeerClient is the other call member: an independent MLS client whose
// media keys are derived from its own store, never from the session's.
type reviewPeerClient struct {
	client  *mls.Client
	store   *memorystore.Store
	groupID []byte
}

func newReviewPeer(t *testing.T) *reviewPeerClient {
	t.Helper()
	id, err := userIDToIdentityBytes(reviewPeer)
	if err != nil {
		t.Fatalf("SETUP: peer identity: %v", err)
	}
	st := memorystore.NewStore()
	c, err := mls.NewClient(id, ciphersuite.MLS128DHKEMP256, mls.WithStorage(st, st), mls.WithCacheStrategy(mls.CacheNone))
	if err != nil {
		t.Fatalf("SETUP: peer client: %v", err)
	}

	return &reviewPeerClient{client: c, store: st}
}

// welcomeFor creates the peer's group with the external sender and invites
// the bot's key package, returning the Welcome.
func (p *reviewPeerClient) welcomeFor(t *testing.T, groupID, botKP, ext []byte) []byte {
	t.Helper()
	ctx := context.Background()
	pkp, err := p.client.FreshKeyPackageBytes(ctx)
	if err != nil {
		t.Fatalf("SETUP: peer key package: %v", err)
	}
	gid, err := p.client.CreateGroupWithExternalSender(ctx, groupID, pkp, ext)
	if err != nil {
		t.Fatalf("SETUP: peer create group: %v", err)
	}
	p.groupID = gid
	_, welcome, err := p.client.InviteMember(ctx, gid, botKP)
	if err != nil {
		t.Fatalf("SETUP: peer invite bot: %v", err)
	}

	return welcome
}

// emptyCommit has the peer commit with no pending proposals.
func (p *reviewPeerClient) emptyCommit(t *testing.T) []byte {
	t.Helper()
	commit, _, err := p.client.CommitPendingProposals(context.Background(), p.groupID)
	if err != nil {
		t.Fatalf("SETUP: peer commit: %v", err)
	}

	return commit
}

// frame encrypts payload as the peer would at its current epoch.
func (p *reviewPeerClient) frame(t *testing.T, nonce uint32, payload []byte) []byte {
	t.Helper()
	base, err := mediakeys.DeriveSenderBaseSecret(exporterAdapter{store: p.store, groupID: p.groupID}, reviewPeerID)
	if err != nil {
		t.Fatalf("SETUP: peer base secret: %v", err)
	}
	r, err := mediakeys.NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("SETUP: peer ratchet: %v", err)
	}
	key, err := r.GetKey(mediakeys.GenerationFromTruncatedNonce(nonce))
	if err != nil {
		t.Fatalf("SETUP: peer key: %v", err)
	}
	out, err := frame.Encrypt(frame.EncryptParams{Plaintext: payload, Key: key, TruncatedNonce: nonce})
	if err != nil {
		t.Fatalf("SETUP: peer frame: %v", err)
	}

	return out
}

func (p *reviewPeerClient) epoch(t *testing.T) uint64 {
	t.Helper()
	e, err := p.client.Epoch(context.Background(), p.groupID)
	if err != nil {
		t.Fatalf("SETUP: peer epoch: %v", err)
	}

	return e
}

// reviewSession is a protocol-1 session that has received the external
// sender package, with the peer announced and an Opus SSRC assigned.
func reviewSession(t *testing.T, cb godave.Callbacks, opts ...Option) (*Session, []byte) {
	t.Helper()
	s := New(reviewBot, cb, opts...)
	s.SetChannelID(reviewChannel)
	s.AssignSsrcToCodec(reviewSSRC, godave.CodecOpus)
	s.AddUser(reviewPeer)
	s.OnSelectProtocolAck(1)
	ext := buildExternalSenderPackage(t)
	s.OnDaveMLSExternalSenderPackage(ext)

	return s, ext
}

// reviewSoleMember is an established sole-member session.
func reviewSoleMember(t *testing.T, opts ...Option) *Session {
	t.Helper()
	s, _ := reviewSession(t, &reviewCallbacks{}, opts...)
	s.OnDavePrepareTransition(0, 1)
	if !s.Ready() {
		t.Fatal("SETUP: sole-member session not ready")
	}

	return s
}

// reviewTwoMember has the peer welcome the bot into a group whose ID is the
// channel ID, at the given transition. Transition 0 activates immediately.
func reviewTwoMember(t *testing.T, transitionID uint16, opts ...Option) (*Session, *reviewPeerClient, *reviewCallbacks) {
	t.Helper()
	cb := &reviewCallbacks{}
	s, ext := reviewSession(t, cb, opts...)
	peer := newReviewPeer(t)
	welcome := peer.welcomeFor(t, reviewChannelGroupID(), cb.lastKeyPackage(), ext)
	s.OnDaveMLSWelcome(transitionID, welcome)
	if got := s.Stats().WelcomesJoined; got != 1 {
		t.Fatalf("SETUP: welcome not joined (stats %+v)", s.Stats())
	}
	if transitionID == 0 && !s.Ready() {
		t.Fatal("SETUP: two-member epoch not active")
	}

	return s, peer, cb
}

func reviewEncrypt(t *testing.T, s *Session, p []byte) []byte {
	t.Helper()
	out := make([]byte, s.MaxEncryptedFrameSize(len(p)))
	n, err := s.Encrypt(reviewSSRC, p, out)
	if err != nil {
		t.Fatalf("SETUP: Encrypt: %v", err)
	}

	return out[:n]
}

// goroutinesIn counts live goroutines whose stack contains every marker.
func goroutinesIn(markers ...string) int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		all := true
		for _, m := range markers {
			if !strings.Contains(g, m) {
				all = false

				break
			}
		}
		if all {
			n++
		}
	}

	return n
}

func reviewInitSecretHex(t *testing.T, s *Session) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	raw, err := s.mlsClient.store.LoadGroupState(context.Background(), group.NewGroupID(s.groupID))
	if err != nil {
		t.Fatalf("SETUP: load bot group state: %v", err)
	}
	g, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("SETUP: unmarshal bot group state: %v", err)
	}

	return hex.EncodeToString(g.EpochSecrets().InitSecret.AsSlice())
}
