package session

import "testing"

func TestAntiReplay_FirstNonceAccepted(t *testing.T) {
	var w antiReplayWindow
	if !w.checkAndMark(10) {
		t.Fatal("first nonce must be accepted")
	}
	if w.highest != 10 || !w.marked(10) {
		t.Fatalf("state mismatch: %s", w.String())
	}
}

func TestAntiReplay_ExactReplayRejected(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(42)
	if w.checkAndMark(42) {
		t.Fatal("exact replay must be rejected")
	}
}

func TestAntiReplay_HigherNonceAccepted(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	if !w.checkAndMark(15) {
		t.Fatal("higher nonce must be accepted")
	}
	if w.highest != 15 {
		t.Fatalf("highest should be 15, got %d", w.highest)
	}
	if !w.marked(15) || !w.marked(10) {
		t.Fatalf("bitmap missing bits: %s", w.String())
	}
}

func TestAntiReplay_LowerNonceWithinWindowRejected(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	w.checkAndMark(15)
	// 10 was already seen.
	if w.checkAndMark(10) {
		t.Fatal("lower nonce already seen must be rejected")
	}
}

func TestAntiReplay_LowerNonceWithinWindowNotSeenAccepted(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(10)
	w.checkAndMark(15)
	// 12 was never seen.
	if !w.checkAndMark(12) {
		t.Fatal("lower nonce never seen within window must be accepted")
	}
	if w.highest != 15 {
		t.Fatalf("highest must not change: got %d", w.highest)
	}
}

func TestAntiReplay_OutsideWindowRejected(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(1)
	w.checkAndMark(replayWindowSize + 2)
	// Nonce 1 is just outside the window, so the window can't tell whether it
	// was seen.
	if w.checkAndMark(1) {
		t.Fatal("nonce outside window must be rejected")
	}
	// Nonce 3 is the oldest the window still tracks, and was never seen.
	if !w.checkAndMark(3) {
		t.Fatal("oldest nonce in the window, never seen, must be accepted")
	}
}

func TestAntiReplay_LateFirstDeliveryAccepted(t *testing.T) {
	var w antiReplayWindow
	for i := uint64(1); i <= 100; i++ {
		if i != 10 {
			w.checkAndMark(i)
		}
	}
	// Nonce 10 arrives 90 behind for the first time, as libdave accepts.
	if !w.checkAndMark(10) {
		t.Fatal("late first delivery within window must be accepted")
	}
	if w.checkAndMark(10) {
		t.Fatal("replay of the late delivery must be rejected")
	}
	// Nonce 1 is 99 behind and was seen, as libdave rejects.
	if w.checkAndMark(1) {
		t.Fatal("replay 99 behind must be rejected")
	}
}

func TestAntiReplay_FirstNonceLeavesEarlierNoncesOpen(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(500)
	if !w.checkAndMark(499) {
		t.Fatal("nonce below the first one seen must be accepted once")
	}
	if w.checkAndMark(499) {
		t.Fatal("replay of 499 must be rejected")
	}
}

func TestAntiReplay_AdvanceClearsReusedSlots(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(5)
	w.checkAndMark(6)
	w.checkAndMark(4 + replayWindowSize)
	// Moving up to 7+replayWindowSize skips 5+replayWindowSize and
	// 6+replayWindowSize, which share slots with 5 and 6.
	w.checkAndMark(7 + replayWindowSize)
	if !w.checkAndMark(5+replayWindowSize) || !w.checkAndMark(6+replayWindowSize) {
		t.Fatal("skipped nonce sharing a slot with a seen one must be accepted")
	}
	// A jump past the whole window clears every slot.
	w.checkAndMark(3*replayWindowSize + 3)
	if !w.checkAndMark(2*replayWindowSize + 5) {
		t.Fatal("never-seen nonce after a jump past the window must be accepted")
	}
}

func TestAntiReplay_WindowFullRejected(t *testing.T) {
	var w antiReplayWindow
	// Fill window: nonces 0..replayWindowSize-1.
	for i := range uint64(replayWindowSize) {
		w.checkAndMark(i)
	}
	// Nonce 0 is the oldest the window tracks and already seen.
	if w.checkAndMark(0) {
		t.Fatal("nonce within window already seen must be rejected")
	}
}

func TestAntiReplay_ResetClearsState(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(99)
	w.checkAndMark(100)
	w.reset()
	if w.seen {
		t.Fatal("reset must clear seen flag")
	}
	// After reset, nonces 100 and 99 must be accepted again.
	if !w.checkAndMark(100) || !w.checkAndMark(99) {
		t.Fatal("nonce must be accepted after reset")
	}
}

func TestAntiReplay_ExactReplaySameNonce(t *testing.T) {
	var w antiReplayWindow
	w.checkAndMark(50)
	// Exact replay of nonce 50.
	if w.checkAndMark(50) {
		t.Fatal("replay of same nonce must be rejected")
	}
}

func TestAntiReplay_OutOfOrderWithinWindow(t *testing.T) {
	var w antiReplayWindow
	// Accept 10, 15, 8 (out of order).
	w.checkAndMark(10)
	w.checkAndMark(15)
	if !w.checkAndMark(8) {
		t.Fatal("out-of-order within window must be accepted")
	}
	// Now replay 8 — must be rejected.
	if w.checkAndMark(8) {
		t.Fatal("replay of 8 must be rejected after it was accepted")
	}
}

// FuzzAntiReplay checks the window against a plain record of every nonce
// accepted.
func FuzzAntiReplay(f *testing.F) {
	f.Add([]byte{1, 2, 3, 2, 1})
	f.Add([]byte{0, 0xff, 0xff, 0, 1})
	f.Fuzz(func(t *testing.T, steps []byte) {
		var w antiReplayWindow
		seen := map[uint64]bool{}
		var highest, nonce uint64
		for i := 0; i+1 < len(steps); i += 2 {
			// Each pair moves the nonce up to two windows either way.
			delta := uint64(steps[i])<<3 | uint64(steps[i+1]>>5)
			if steps[i+1]&1 == 0 && nonce >= delta {
				nonce -= delta
			} else {
				nonce += delta
			}
			want := len(seen) == 0 || nonce > highest ||
				(highest-nonce < replayWindowSize && !seen[nonce])
			if got := w.checkAndMark(nonce); got != want {
				t.Fatalf("nonce %d (highest %d): got %v, want %v", nonce, highest, got, want)
			}
			if want {
				seen[nonce] = true
				if nonce > highest || len(seen) == 1 {
					highest = nonce
				}
			}
		}
	})
}
