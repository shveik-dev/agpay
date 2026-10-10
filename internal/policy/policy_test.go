package policy

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedPolicyRejectsTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "policy.json")
	salt := NewSalt()
	k, err := AdminKey("admin passphrase", salt)
	if err != nil {
		t.Fatal(err)
	}
	pub := hex.EncodeToString(k.Public().(ed25519.PublicKey))
	if err := Save(p, Defaults(), k, salt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p, pub); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	os.WriteFile(p, []byte(strings.Replace(string(b), "10000000", "99000000", 1)), 0o600)
	if _, _, err := Load(p, pub); err == nil {
		t.Fatal("tampered policy accepted")
	}
	os.Remove(p)
	if _, _, err := Load(p, pub); err == nil {
		t.Fatal("missing policy accepted under an admin key")
	}
	if r, _, err := Load(p, ""); err != nil || r.MaxPayment != "1000000" {
		t.Fatal("defaults", err)
	}
}

func TestLedgerLimits(t *testing.T) {
	l := Ledger{Path: filepath.Join(t.TempDir(), "spend.jsonl")}
	r := Defaults()
	now := time.Now()
	if err := l.Reserve(r, Entry{ID: "a", Amount: "1000001", Kind: "exact"}, now); err == nil {
		t.Fatal("per-payment limit not enforced")
	}
	for i := 0; i < 10; i++ {
		if err := l.Reserve(r, Entry{ID: NewID(), Amount: "1000000", Kind: "exact"}, now); err != nil {
			t.Fatal(i, err)
		}
	}
	if err := l.Reserve(r, Entry{ID: "x", Amount: "1", Kind: "exact"}, now); err == nil {
		t.Fatal("daily limit not enforced")
	}
	// a reservation whose authorization expired without settling frees the budget
	if err := l.Reserve(r, Entry{ID: "y", Amount: "1", Kind: "exact"}, now.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := l.Reserve(r, Entry{ID: "d", Amount: "5000001", Kind: "deposit"}, now.Add(48*time.Hour)); err == nil {
		t.Fatal("deposit cap not enforced")
	}
}

func TestHostMatching(t *testing.T) {
	r := Rules{Hosts: []string{"agdata.shveik.dev", "*.example.com"}}
	if !r.HostOK("AGDATA.shveik.dev") || !r.HostOK("a.example.com") || r.HostOK("evil.com") || r.HostOK("example.com") {
		t.Fatal("host match")
	}
}

func TestLedgerTamperDetected(t *testing.T) {
	dir := t.TempDir()
	l := Ledger{Path: dir + "/s.jsonl", Key: []byte("0123456789abcdef0123456789abcdef")}
	r := Defaults()
	now := time.Now()
	for i := 0; i < 3; i++ {
		if err := l.Reserve(r, Entry{ID: NewID(), Amount: "500000", Kind: "exact"}, now); err != nil {
			t.Fatal(err)
		}
	}
	if s, err := l.Spent(now); err != nil || s.String() != "1500000" {
		t.Fatal(s, err)
	}
	b, _ := os.ReadFile(l.Path)
	// lower one amount: the chain breaks, spending is refused
	edited := strings.Replace(string(b), `"amount_atomic":"500000"`, `"amount_atomic":"5"`, 1)
	os.WriteFile(l.Path, []byte(edited), 0o600)
	if err := l.Reserve(r, Entry{ID: "z", Amount: "1", Kind: "exact"}, now); err != ErrTampered {
		t.Fatal("edit not detected:", err)
	}
	// drop the first line: also detected
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	os.WriteFile(l.Path, []byte(strings.Join(lines[1:], "\n")+"\n"), 0o600)
	if _, err := l.Spent(now); err != ErrTampered {
		t.Fatal("deleted line not detected:", err)
	}
	// a different key cannot read it
	os.WriteFile(l.Path, b, 0o600)
	if _, err := (Ledger{Path: l.Path, Key: []byte("another key another key another!")}).Spent(now); err != ErrTampered {
		t.Fatal("wrong key accepted")
	}
}
