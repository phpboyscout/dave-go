package session

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// reviewFlakyCallbacks fails the first `fails` key-package sends with the
// transient error retrySend backs off on, and signals the first failure.
type reviewFlakyCallbacks struct {
	reviewCallbacks
	mu        sync.Mutex
	fails     int
	firstFail chan struct{}
	once      sync.Once
}

func (c *reviewFlakyCallbacks) SendMLSKeyPackage(kp []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fails > 0 {
		c.fails--
		c.once.Do(func() { close(c.firstFail) })

		return errors.New("shard is not ready")
	}

	return c.reviewCallbacks.SendMLSKeyPackage(kp)
}

type reviewReentrantCallbacks struct {
	reviewCallbacks
	s *Session
}

func (c *reviewReentrantCallbacks) SendMLSKeyPackage(kp []byte) error {
	_ = c.s.State()

	return c.reviewCallbacks.SendMLSKeyPackage(kp)
}

// C-5. Correct: Ready() answers promptly while a gateway handler is in retry
// back-off. Trigger: two "shard is not ready" key-package failures during
// select_protocol_ack, at a 300 ms initial back-off (900 ms in total).
// retryDelay is set in-package because retry_test.go's init() zeroes it for
// the whole package (R-15); it is restored afterwards.
func TestReview_C5_ReadyMustNotBlockDuringRetryBackoff(t *testing.T) {
	old := retryDelay
	retryDelay = 300 * time.Millisecond
	t.Cleanup(func() { retryDelay = old })

	cb := &reviewFlakyCallbacks{fails: 2, firstFail: make(chan struct{})}
	s := New(reviewBot, cb)
	handlerDone := make(chan struct{})
	go func() {
		s.OnSelectProtocolAck(1)
		close(handlerDone)
	}()
	select {
	case <-cb.firstFail:
	case <-time.After(5 * time.Second):
		t.Fatal("SETUP: key-package send never attempted")
	}

	readyDone := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		_ = s.Ready()
		readyDone <- time.Since(start)
	}()
	select {
	case <-readyDone:
	case <-time.After(150 * time.Millisecond):
		blocked := <-readyDone
		t.Errorf("C-5: Ready() blocked for %v while OnSelectProtocolAck slept through retry back-off holding the session lock; want it to return at once", blocked.Round(time.Millisecond))
	}
	<-handlerDone
}

// C-5. Correct: a callback may call back into the session (State() here)
// without deadlocking it. Trigger: SendMLSKeyPackage calls s.State(). On
// failure the handler goroutine stays blocked for the rest of the test binary.
func TestReview_C5_CallbackCallingStateMustNotDeadlock(t *testing.T) {
	cb := &reviewReentrantCallbacks{}
	s := New(reviewBot, cb)
	cb.s = s
	done := make(chan struct{})
	go func() {
		s.OnSelectProtocolAck(1)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("C-5: OnSelectProtocolAck did not return within 2 s after its SendMLSKeyPackage callback called s.State(): the session is deadlocked")
	}
}
