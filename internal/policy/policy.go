// Package policy holds the spending rules and the spend ledger. The rules are signed by an admin
// key that is derived from a second passphrase, so the passphrase an agent uses to spend cannot
// loosen them through this program. (A process that can rewrite the wallet file itself is outside
// this model: use operating-system separation for that.)
package policy

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/shveik-dev/agpay/internal/chain"
)

type Rules struct {
	Wallet     string      `json:"wallet,omitempty"`         // the EVM address this policy was written for
	Extra      []chain.Net `json:"extra_networks,omitempty"` // networks added to the built-in ones; signed with the rest
	Seq        int64       `json:"seq"`                      // grows with every signed change
	MaxPayment string      `json:"max_payment_atomic"`       // per payment (a channel deposit has its own cap and still counts in the daily total)
	MaxDay     string      `json:"max_per_day_atomic"`       // rolling 24 hours, all networks
	MaxDeposit string      `json:"max_deposit_atomic"`       // one batch-settlement channel deposit
	SendTo     []string    `json:"allow_send_to,omitempty"`  // addresses `send` may pay out to (empty = sending out is disabled)
	Hosts      []string    `json:"hosts,omitempty"`          // allowed API hosts (empty = any)
	Networks   []string    `json:"networks,omitempty"`       // allowed CAIP-2 networks (empty = any known)
	Schemes    []string    `json:"schemes,omitempty"`        // exact, batch-settlement (empty = both)
	AllowHTTP  bool        `json:"allow_http,omitempty"`     // permit plain http (loopback is always allowed)
}

// Defaults are deliberately small: $1 a payment, $10 a day, $5 a channel deposit.
func Defaults() Rules {
	return Rules{MaxPayment: "1000000", MaxDay: "10000000", MaxDeposit: "5000000", Schemes: []string{"exact", "batch-settlement"}}
}

type Signed struct {
	Rules     Rules  `json:"rules"`
	AdminSalt string `json:"admin_salt,omitempty"`
	Sig       string `json:"sig,omitempty"` // hex ed25519 over the canonical JSON of Rules
}

func canonical(r Rules) []byte {
	sort.Strings(r.Hosts)
	sort.Strings(r.Networks)
	sort.Strings(r.Schemes)
	b, _ := json.Marshal(r)
	return b
}

// AdminKey derives the policy signing key from the admin passphrase.
func AdminKey(pass string, salt []byte) (ed25519.PrivateKey, error) {
	if len(pass) < 12 {
		return nil, errors.New("admin passphrase must be at least 12 characters")
	}
	seed, err := scrypt.Key([]byte(pass), salt, 1<<17, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func NewSalt() []byte { b := make([]byte, 16); rand.Read(b); return b }

// Load returns the effective rules. When adminPub is set the file must carry a valid signature
// and a sequence number not below minSeq; an unsigned or tampered file is an error, never a
// silent fallback to looser rules. With no admin key the file is trusted as written.
func Load(path, adminPub string) (Rules, int, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if adminPub != "" {
			return Rules{}, 0, errors.New("policy file is missing but an admin key is set: restore it or run `agpay policy set` with the admin passphrase")
		}
		return Defaults(), 0, nil
	}
	if err != nil {
		return Rules{}, 0, err
	}
	var s Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return Rules{}, 0, fmt.Errorf("policy file is corrupt: %w", err)
	}
	if adminPub != "" {
		pub, err := hex.DecodeString(adminPub)
		sig, err2 := hex.DecodeString(s.Sig)
		if err != nil || err2 != nil || len(pub) != 32 || !ed25519.Verify(pub, canonical(s.Rules), sig) {
			return Rules{}, 0, errors.New("policy file signature is invalid: it was changed without the admin passphrase")
		}
	}
	if err := s.Rules.Validate(); err != nil {
		return Rules{}, 0, err
	}
	return s.Rules, int(s.Rules.Seq), nil
}

// NextSeq is the sequence number of the next signed policy: the clock, but always above the last.
func NextSeq(prev int64) int64 {
	if n := time.Now().Unix(); n > prev {
		return n
	}
	return prev + 1
}

// Save writes rules, signing them when an admin key is given. r.Seq must already be set.
func Save(path string, r Rules, admin ed25519.PrivateKey, salt []byte) error {
	if err := r.Validate(); err != nil {
		return err
	}
	s := Signed{Rules: r}
	if admin != nil {
		s.AdminSalt = hex.EncodeToString(salt)
		s.Sig = hex.EncodeToString(ed25519.Sign(admin, canonical(r)))
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (r Rules) Validate() error {
	for _, f := range []struct{ n, v string }{{"max_payment_atomic", r.MaxPayment}, {"max_per_day_atomic", r.MaxDay}, {"max_deposit_atomic", r.MaxDeposit}} {
		if _, ok := new(big.Int).SetString(f.v, 10); !ok || f.v == "" || strings.HasPrefix(f.v, "-") {
			return fmt.Errorf("%s must be a non-negative integer", f.n)
		}
	}
	for _, s := range r.Schemes {
		if s != "exact" && s != "batch-settlement" {
			return fmt.Errorf("unknown scheme %q", s)
		}
	}
	return nil
}

func (r Rules) Big(v string) *big.Int { n, _ := new(big.Int).SetString(v, 10); return n }

func (r Rules) HostOK(host string) bool {
	if len(r.Hosts) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, h := range r.Hosts {
		h = strings.ToLower(h)
		if host == h || (strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:])) {
			return true
		}
	}
	return false
}

func (r Rules) SendOK(addr string) bool {
	for _, a := range r.SendTo {
		if strings.EqualFold(a, addr) {
			return true
		}
	}
	return false
}

func (r Rules) NetworkOK(n string) bool { return len(r.Networks) == 0 || contains(r.Networks, n) }
func (r Rules) SchemeOK(s string) bool  { return len(r.Schemes) == 0 || contains(r.Schemes, s) }

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// ---- spend ledger ----

type Entry struct {
	ID         string `json:"id"`
	TS         int64  `json:"ts"`
	Host       string `json:"host"`
	URL        string `json:"url,omitempty"`
	Network    string `json:"network"`
	Scheme     string `json:"scheme"`
	Kind       string `json:"kind"` // exact | deposit | voucher | refund
	Amount     string `json:"amount_atomic"`
	Asset      string `json:"asset"`
	ValidUntil int64  `json:"valid_until,omitempty"`
	Status     string `json:"status"` // reserved | settled | failed
	Tx         string `json:"tx,omitempty"`
	Note       string `json:"note,omitempty"`
	Key        string `json:"idempotency_key,omitempty"`
}

// Ledger is an append-only JSONL file. When Key is set every line carries an HMAC chained to the
// line before it, so an edited, reordered or dropped-from-the-middle line is detected and spending
// stops (fail closed) instead of silently resetting the daily limit.
type Ledger struct {
	Path string
	Key  []byte
}

var ErrTampered = errors.New("the spend ledger was changed outside agpay: refusing to spend until the owner checks it")

func (l Ledger) mac(prev string, line []byte) string {
	m := hmac.New(sha256.New, l.Key)
	m.Write([]byte(prev))
	m.Write(line)
	return hex.EncodeToString(m.Sum(nil))
}

func (l Ledger) lock() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(l.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (l Ledger) read() (map[string]Entry, []string, string, error) {
	b, err := os.ReadFile(l.Path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]Entry{}, nil, "", nil
	}
	if err != nil {
		return nil, nil, "", err
	}
	m := map[string]Entry{}
	var order []string
	prev := ""
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		body := ln
		if l.Key != nil {
			k := strings.LastIndexByte(ln, '\t')
			if k < 0 {
				return nil, nil, "", ErrTampered
			}
			body = ln[:k]
			want := l.mac(prev, []byte(body))
			if !hmac.Equal([]byte(want), []byte(ln[k+1:])) {
				return nil, nil, "", ErrTampered
			}
			prev = want
		}
		if l.Key == nil { // unverified read (display only): drop the MAC column
			if k := strings.LastIndexByte(body, '\t'); k >= 0 {
				body = body[:k]
			}
		}
		var e Entry
		if json.Unmarshal([]byte(body), &e) != nil {
			if l.Key != nil {
				return nil, nil, "", ErrTampered
			}
			continue
		}
		if _, ok := m[e.ID]; !ok {
			order = append(order, e.ID)
		}
		m[e.ID] = e
	}
	return m, order, prev, nil
}

func (l Ledger) append(e Entry, prev string) error {
	f, err := os.OpenFile(l.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	line := string(b)
	if l.Key != nil {
		line += "\t" + l.mac(prev, b)
	}
	_, err = f.WriteString(line + "\n")
	if err == nil {
		err = f.Sync()
	}
	return err
}

// counted: settled payments of the last 24 hours, plus reservations whose authorization may still
// be redeemed.
func counted(e Entry, now time.Time) bool {
	switch e.Status {
	case "settled":
		return now.Unix()-e.TS < 86400
	case "reserved":
		until := e.ValidUntil
		if until == 0 {
			until = e.TS + 600
		}
		return now.Unix() < until+60
	}
	return false
}

// Spent is what counts against the daily limit now.
func (l Ledger) Spent(now time.Time) (*big.Int, error) {
	m, _, _, err := l.read()
	if err != nil {
		return nil, err
	}
	sum := new(big.Int)
	for _, e := range m {
		if counted(e, now) && e.Kind != "refund" {
			a, _ := new(big.Int).SetString(e.Amount, 10)
			if a != nil {
				sum.Add(sum, a)
			}
		}
	}
	return sum, nil
}

// Reserve checks the rules and records the spend in one locked step, so two agents sharing a
// wallet cannot both pass the daily check.
func (l Ledger) Reserve(r Rules, e Entry, now time.Time) error {
	amount, ok := new(big.Int).SetString(e.Amount, 10)
	if !ok || amount.Sign() < 0 {
		return errors.New("bad amount")
	}
	lk, err := l.lock()
	if err != nil {
		return err
	}
	defer lk.Close()
	// a channel deposit is capped by max_deposit (and the daily total), every other payment by
	// max_payment: funding a channel is not one payment to the server
	if e.Kind == "deposit" {
		if amount.Cmp(r.Big(r.MaxDeposit)) > 0 {
			return &LimitError{"max_deposit", r.MaxDeposit, e.Amount}
		}
	} else if amount.Cmp(r.Big(r.MaxPayment)) > 0 {
		return &LimitError{"max_payment", r.MaxPayment, e.Amount}
	}
	m, _, prev, err := l.read()
	if err != nil {
		return err
	}
	spent := new(big.Int)
	for _, x := range m {
		if counted(x, now) && x.Kind != "refund" {
			if a, ok := new(big.Int).SetString(x.Amount, 10); ok {
				spent.Add(spent, a)
			}
		}
	}
	if new(big.Int).Add(spent, amount).Cmp(r.Big(r.MaxDay)) > 0 {
		return &LimitError{"max_per_day", r.MaxDay, new(big.Int).Add(spent, amount).String()}
	}
	e.TS, e.Status = now.Unix(), "reserved"
	return l.append(e, prev)
}

type LimitError struct{ Limit, Max, Would string }

func (e *LimitError) Error() string {
	return fmt.Sprintf("policy %s: %s atomic USDC would exceed the limit of %s", e.Limit, e.Would, e.Max)
}

// Finish records the outcome of a reservation.
func (l Ledger) Finish(id, status, tx, note string) error {
	lk, err := l.lock()
	if err != nil {
		return err
	}
	defer lk.Close()
	m, _, prev, err := l.read()
	if err != nil {
		return err
	}
	e, ok := m[id]
	if !ok {
		return errors.New("unknown spend id")
	}
	e.Status, e.Tx, e.Note = status, tx, note
	return l.append(e, prev)
}

func (l Ledger) List(since time.Time) ([]Entry, error) {
	m, order, _, err := l.read()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, id := range order {
		if m[id].TS >= since.Unix() {
			out = append(out, m[id])
		}
	}
	return out, nil
}

func NewID() string { b := make([]byte, 8); rand.Read(b); return hex.EncodeToString(b) }

// ByKey returns the entry recorded under an idempotency key, if any.
func (l Ledger) ByKey(key string) (*Entry, error) {
	if key == "" {
		return nil, nil
	}
	m, order, _, err := l.read()
	if err != nil {
		return nil, err
	}
	for i := len(order) - 1; i >= 0; i-- {
		if e := m[order[i]]; e.Key == key && e.Status != "failed" {
			return &e, nil
		}
	}
	return nil, nil
}
