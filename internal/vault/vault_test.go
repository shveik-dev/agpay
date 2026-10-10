package vault

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCreateOpenRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.json")
	seed, _ := NewSeed()
	s, err := Derive(seed)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Create(p, s, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatal("mode", st.Mode())
	}
	w, err := Open(p, "correct horse battery")
	if err != nil || w.EVM != v.EVM || w.Solana != v.Solana || w.Secrets.EVMKey != s.EVMKey {
		t.Fatal(err)
	}
	if _, err := Open(p, "wrong passphrase!"); err != ErrWrongPassphrase {
		t.Fatal(err)
	}
	if _, err := Create(p, s, "correct horse battery"); err == nil {
		t.Fatal("overwrote an existing wallet")
	}
	ea, sa, err := Public(p)
	if err != nil || ea != v.EVM || sa != v.Solana {
		t.Fatal("public", err)
	}
	// the file must not contain the key material
	b, _ := os.ReadFile(p)
	if contains(b, s.EVMKey) || contains(b, s.SolSeed) || contains(b, s.Seed) {
		t.Fatal("secret in clear")
	}
}

func TestDeriveIsDeterministic(t *testing.T) {
	seed := make([]byte, 32)
	a, _ := Derive(seed)
	b, _ := Derive(seed)
	if a != b || a.EVMKey == a.SolSeed {
		t.Fatal("derive")
	}
}

func contains(b []byte, s string) bool {
	return len(s) > 0 && string(b) != "" && indexOf(string(b), s) >= 0
}
func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
