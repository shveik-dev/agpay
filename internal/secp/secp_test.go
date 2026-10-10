package secp

import (
	"bytes"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

func keccak(b []byte) []byte { h := sha3.NewLegacyKeccak256(); h.Write(b); return h.Sum(nil) }

func TestKnownAddress(t *testing.T) {
	// private key 1 -> address 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf (well-known test vector)
	k := make([]byte, 32)
	k[31] = 1
	pub, err := PublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(keccak(pub)[12:])
	if got != "7e5f4552091a69125d5dfcb7b8c2659029395bdf" {
		t.Fatal(got)
	}
}

func TestSignRecoverRoundTrip(t *testing.T) {
	for i := 1; i < 40; i++ {
		k := keccak([]byte{byte(i)})
		h := keccak([]byte("msg"))
		h[0] = byte(i)
		sig, err := Sign(k, h)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := Recover(h, sig)
		if err != nil {
			t.Fatal(err)
		}
		want, _ := PublicKey(k)
		if !bytes.Equal(pub, want) {
			t.Fatalf("recover mismatch %d", i)
		}
		again, _ := Sign(k, h)
		if !bytes.Equal(again, sig) {
			t.Fatal("not deterministic")
		}
	}
}
