package client

import (
	"testing"
	"time"
)

// TestHandshakeDoneSignalsOnce verifies signalHandshakeDone is idempotent
// and unblocks any waiter on handshakeDone.
func TestHandshakeDoneSignalsOnce(t *testing.T) {
	c := &HytaleClient{
		handshakeDone: make(chan struct{}),
	}

	// Should not block — channel is closed by the first call.
	c.signalHandshakeDone()

	select {
	case <-c.handshakeDone:
		// ok
	case <-time.After(time.Second):
		t.Fatal("handshakeDone was not closed after signalHandshakeDone")
	}

	// Second call must be a no-op (no panic from double close).
	c.signalHandshakeDone()
}

// TestHandshakeDoneNilSafe verifies signalHandshakeDone tolerates a
// zero-value client (handshakeDone == nil), which is the state before
// Connect has run.
func TestHandshakeDoneNilSafe(t *testing.T) {
	c := &HytaleClient{}
	// Should not panic.
	c.signalHandshakeDone()
}
