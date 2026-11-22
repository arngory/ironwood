package encrypted

import (
	"math/rand"
	"testing"
)

// the pre-merge through(n), verbatim from e938161
func (w *replayWindow) r7through(n uint64) {
	w.head = n
	for i := range w.ring {
		w.ring[i] = ^uint64(0)
	}
	w.ring[(n/replayBlockBits)&replayBlockMask] = ^uint64(0) >> (replayBlockBits - 1 - n%replayBlockBits)
}

func TestR7ThroughEqualsResetAt(t *testing.T) {
	vals := []uint64{0, 1, 62, 63, 64, 65, 127, 128, 8191, 8192, 8193, ^uint64(0), ^uint64(0) - 1, 1 << 63}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 100000; i++ {
		vals = append(vals, r.Uint64(), uint64(r.Intn(1<<20)))
	}
	for _, n := range vals {
		var a, b replayWindow
		a.reset()
		b.reset()
		a.r7through(n)
		b.resetAt(n)
		if a != b {
			t.Fatalf("differ at %d", n)
		}
	}
}
