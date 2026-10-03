package session

import (
	"context"
	"encoding/hex"
	"log/slog"
	"strings"
	"testing"

	"github.com/thomas-vilte/dave-go/mediakeys"
	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/schedule"
)

// captureDefaultLogger points slog.Default at a debug-level buffer for the
// test, because some lines bypass the configured logger (C-9) and mls-go logs
// there too.
func captureDefaultLogger(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	old := slog.Default()
	slog.SetDefault(reviewDebugLogger(buf))
	t.Cleanup(func() { slog.SetDefault(old) })

	return buf
}

// hexWindows returns every 6-byte window of secret, in lower and upper hex, so
// a match does not depend on which slice of the secret a log line chose.
func hexWindows(secret []byte) []string {
	const w = 6
	var out []string
	for i := 0; i+w <= len(secret); i++ {
		h := hex.EncodeToString(secret[i : i+w])
		out = append(out, h, strings.ToUpper(h))
	}

	return out
}

func firstLineContaining(logs string, needles []string) (string, bool) {
	for _, line := range strings.Split(logs, "\n") {
		for _, n := range needles {
			if strings.Contains(line, n) {
				return line, true
			}
		}
	}

	return "", false
}

// C-4. Correct: no log line, at any level, contains the bot's current-epoch
// init_secret. Trigger: the peer sends a commit whose confirmation tag is
// flipped and whose membership tag is recomputed, so it reaches mls-go's
// confirmation-tag check.
func TestReview_C4_LogsMustNotContainInitSecret(t *testing.T) {
	ctx := context.Background()
	defaultLogs := captureDefaultLogger(t)
	sessionLogs := &syncBuffer{}
	s, peer, _ := reviewTwoMember(t, 0, WithLogger(reviewDebugLogger(sessionLogs)))

	raw, err := peer.store.LoadGroupState(ctx, group.NewGroupID(peer.groupID))
	if err != nil {
		t.Fatalf("SETUP: load peer state: %v", err)
	}
	pg, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("SETUP: unmarshal peer state: %v", err)
	}
	membershipKey := pg.EpochSecrets().MembershipKey
	groupContext := pg.GroupContext().Marshal()

	msg, err := framing.UnmarshalMLSMessage(peer.emptyCommit(t))
	if err != nil {
		t.Fatalf("SETUP: parse commit: %v", err)
	}
	pm, ok := msg.AsPublic()
	if !ok {
		t.Fatal("SETUP: commit is not a PublicMessage")
	}
	pm.Auth.ConfirmationTag[0] ^= 1
	ac := &framing.AuthenticatedContent{WireFormat: framing.WireFormatPublicMessage, Content: pm.Content, Auth: pm.Auth, GroupContext: groupContext}
	pm.MembershipTag = schedule.ComputeMembershipTag(ciphersuite.MLS128DHKEMP256, membershipKey.AsSlice(), ac.MarshalTBM())
	badCommit := framing.NewMLSMessagePublic(pm).Marshal()

	initSecret := reviewInitSecretHex(t, s)
	s.OnDaveMLSPrepareCommitTransition(7, badCommit)
	if got := s.Stats().CommitsFailed; got != 1 {
		t.Fatalf("SETUP: tampered commit was not rejected (CommitsFailed=%d)", got)
	}
	if !strings.Contains(strings.ToLower(sessionLogs.String()), "confirmation tag") {
		t.Fatal("SETUP: the commit was rejected before mls-go's confirmation-tag check; the C-4 path was not reached")
	}

	needles := []string{initSecret, strings.ToUpper(initSecret)}
	for name, logs := range map[string]string{"configured logger": sessionLogs.String(), "slog.Default": defaultLogs.String()} {
		if line, found := firstLineContaining(logs, needles); found {
			t.Errorf("C-4: %s line contains the bot's init_secret %s…: %.300s", name, initSecret[:16], line)
		}
	}
}

// C-9. Correct: debug logs carry no bytes of any sender's base secret, media
// key or the exporter secret. Trigger: a sole-member epoch activates with
// debug logging on.
func TestReview_C9_DebugLogsMustNotContainKeyMaterial(t *testing.T) {
	defaultLogs := captureDefaultLogger(t)
	sessionLogs := &syncBuffer{}
	s := reviewSoleMember(t, WithLogger(reviewDebugLogger(sessionLogs)))
	logs := map[string]string{"configured logger": sessionLogs.String(), "slog.Default": defaultLogs.String()}
	slog.SetDefault(slog.New(slog.DiscardHandler))

	s.mu.Lock()
	exp := exporterAdapter{store: s.mlsClient.store, groupID: s.groupID}
	raw, err := s.mlsClient.store.LoadGroupState(context.Background(), group.NewGroupID(s.groupID))
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("SETUP: load bot state: %v", err)
	}
	g, err := group.UnmarshalGroupState(raw)
	if err != nil {
		t.Fatalf("SETUP: unmarshal bot state: %v", err)
	}
	base, err := mediakeys.DeriveSenderBaseSecret(exp, 123456789)
	if err != nil {
		t.Fatalf("SETUP: base secret: %v", err)
	}
	r, err := mediakeys.NewKeyRatchet(base)
	if err != nil {
		t.Fatalf("SETUP: ratchet: %v", err)
	}
	key0, err := r.GetKey(0)
	if err != nil {
		t.Fatalf("SETUP: generation-0 key: %v", err)
	}

	secrets := map[string][]byte{
		"sender base secret":  base,
		"generation-0 key":    key0,
		"MLS exporter secret": g.EpochSecrets().ExporterSecret.AsSlice(),
	}
	for logName, text := range logs {
		for secretName, secret := range secrets {
			if line, found := firstLineContaining(text, hexWindows(secret)); found {
				t.Errorf("C-9: %s line contains bytes of the bot's %s: %.300s", logName, secretName, line)
			}
		}
	}
}
