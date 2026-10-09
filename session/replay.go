package session

import "fmt"

// replayWindowSize is how many nonces below the highest the window tracks.
// It covers libdave's 1000 missing nonces; anything older is refused.
const (
	replayWindowSize = 1024
	bitsPerWord      = 64
)

// antiReplayWindow implements a sliding window anti-replay check. It tracks
// the highest nonce seen and, in a ring indexed by nonce, which of the
// replayWindowSize nonces below it have been seen. A nonce already seen, or
// too old for the window to say, is rejected.
//
// NOT safe for concurrent use. The caller (session.Decrypt) must
// synchronize externally.
type antiReplayWindow struct {
	highest uint64
	bitmap  [replayWindowSize / bitsPerWord]uint64
	seen    bool
}

// checkAndMark records nonce and returns true if it's new (not a replay).
// Returns false if the nonce was already seen or is outside the window.
func (w *antiReplayWindow) checkAndMark(nonce uint64) bool {
	if !w.seen {
		w.highest = nonce
		w.seen = true
		w.mark(nonce)

		return true
	}

	if nonce > w.highest {
		w.advance(nonce)
		w.mark(nonce)

		return true
	}

	if w.highest-nonce >= replayWindowSize || w.marked(nonce) {
		return false
	}
	w.mark(nonce)

	return true
}

// advance moves highest up to nonce, clearing the slots of the nonces it
// skips so they read as unseen.
func (w *antiReplayWindow) advance(nonce uint64) {
	if nonce-w.highest >= replayWindowSize {
		w.bitmap = [replayWindowSize / bitsPerWord]uint64{}
	} else {
		for n := w.highest + 1; n < nonce; n++ {
			word, bit := slot(n)
			w.bitmap[word] &^= bit
		}
	}
	w.highest = nonce
}

func (w *antiReplayWindow) mark(nonce uint64) {
	word, bit := slot(nonce)
	w.bitmap[word] |= bit
}

func (w *antiReplayWindow) marked(nonce uint64) bool {
	word, bit := slot(nonce)

	return w.bitmap[word]&bit != 0
}

func slot(nonce uint64) (word int, bit uint64) {
	i := nonce % replayWindowSize

	return int(i / bitsPerWord), 1 << (i % bitsPerWord)
}

// reset clears the anti-replay window state.
func (w *antiReplayWindow) reset() {
	w.highest = 0
	w.bitmap = [replayWindowSize / bitsPerWord]uint64{}
	w.seen = false
}

func (w *antiReplayWindow) String() string {
	return fmt.Sprintf("antiReplayWindow{highest=%d, seen=%v, bitmap=%x}",
		w.highest, w.seen, w.bitmap)
}
