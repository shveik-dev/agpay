package secp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Signatures made by the server's decred-based implementation must be reproduced bit for bit
// (both are deterministic RFC 6979 and low-s).
func TestGoldenAgainstServerImplementation(t *testing.T) {
	var g struct {
		Sigs []struct{ Key, Hash, Sig string }
	}
	b, err := os.ReadFile("../../testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &g)
	if len(g.Sigs) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range g.Sigs {
		k, _ := hex.DecodeString(v.Key)
		h, _ := hex.DecodeString(v.Hash)
		want, _ := hex.DecodeString(v.Sig)
		got, err := Sign(k, h)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("key %s:\n got %x\nwant %x (%v)", v.Key, got, want, err)
		}
	}
}
