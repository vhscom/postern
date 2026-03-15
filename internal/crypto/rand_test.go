package crypto

import "testing"

func TestRandomHexLength(t *testing.T) {
	for _, n := range []int{8, 16, 32} {
		s := RandomHex(n)
		if len(s) != n*2 {
			t.Errorf("RandomHex(%d) = %q, want %d hex chars", n, s, n*2)
		}
	}
}

func TestRandomHexUnique(t *testing.T) {
	a := RandomHex(32)
	b := RandomHex(32)
	if a == b {
		t.Error("two RandomHex calls returned identical values")
	}
}
