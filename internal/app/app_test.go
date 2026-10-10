package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type out struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  struct {
		Code string `json:"code"`
		Exit int    `json:"exit_code"`
	} `json:"error"`
}

func run(t *testing.T, home string, env map[string]string, args ...string) (int, out, string) {
	t.Helper()
	var so, se bytes.Buffer
	code := Run(&Env{Args: args, Home: home, Stdin: strings.NewReader(""), Stdout: &so, Stderr: &se, Getenv: func(k string) string { return env[k] }})
	var o out
	if err := json.Unmarshal(so.Bytes(), &o); err != nil {
		t.Fatalf("stdout is not one JSON document: %q (%v)", so.String(), err)
	}
	return code, o, so.String()
}

func TestInitAddressAndExitCodes(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	pf := filepath.Join(t.TempDir(), "pass")
	env := map[string]string{"AGPAY_PASSPHRASE_FILE": pf}
	if c, o, _ := run(t, home, env, "init", "--generate-passphrase-file", pf); c != 0 || !o.OK {
		t.Fatal(c, o)
	}
	if c, o, _ := run(t, home, env, "init", "--generate-passphrase-file", filepath.Join(t.TempDir(), "p2")); c != 6 || o.Error.Code != "wallet_exists" {
		t.Fatal("second init", c, o)
	}
	c, o, raw := run(t, home, nil, "address")
	if c != 0 || !strings.Contains(raw, `"evm":"0x`) {
		t.Fatal(c, raw)
	}
	_ = o
	if c, o, _ := run(t, home, nil, "pay", "https://example.com"); c != 6 || o.Error.Code != "passphrase_required" {
		t.Fatal("no passphrase", c, o)
	}
	if c, o, _ := run(t, home, map[string]string{"AGPAY_PASSPHRASE": "wrong passphrase!"}, "pay", "https://example.com"); c != 6 || o.Error.Code != "wrong_passphrase" {
		t.Fatal("wrong passphrase", c, o)
	}
	if c, _, _ := run(t, home, nil, "nope"); c != 2 {
		t.Fatal("unknown command exit", c)
	}
	st, _ := os.Stat(filepath.Join(home, "wallet.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatal("wallet mode")
	}
	if c, _, raw := run(t, home, nil, "describe"); c != 0 || !strings.Contains(raw, `"exit_codes"`) || !strings.Contains(raw, `"idempotency-key"`) {
		t.Fatal("describe", c)
	}
}

func paidServer(t *testing.T, amount string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString([]byte(`{"success":true,"transaction":"0xfeed"}`)))
			w.Write([]byte(`{"data":42}`))
			return
		}
		b, _ := json.Marshal(map[string]any{"x402Version": 2, "accepts": []map[string]any{{"scheme": "exact", "network": "eip155:8453", "amount": amount,
			"asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "payTo": "0xbBa594F5549392DF7A8182049291b605948F5F86", "maxTimeoutSeconds": 120,
			"extra": map[string]any{"name": "USD Coin", "version": "2"}}}})
		w.Header().Set("PAYMENT-REQUIRED", base64.StdEncoding.EncodeToString(b))
		w.WriteHeader(402)
	}))
}

func TestPayWithPolicyAndIdempotency(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	pf := filepath.Join(t.TempDir(), "pass")
	af := filepath.Join(t.TempDir(), "admin")
	env := map[string]string{"AGPAY_PASSPHRASE_FILE": pf, "AGPAY_ADMIN_PASSPHRASE_FILE": af}
	if c, o, _ := run(t, home, nil, "init", "--generate-passphrase-file", pf, "--generate-admin-passphrase-file", af); c != 0 {
		t.Fatal(c, o)
	}
	srv := paidServer(t, "31665")
	defer srv.Close()

	// dry run: nothing signed, nothing spent
	c, _, raw := run(t, home, env, "pay", srv.URL+"/x", "--dry-run")
	if c != 0 || !strings.Contains(raw, `"would_pay"`) {
		t.Fatal(c, raw)
	}
	if c, _, raw := run(t, home, env, "history"); c != 0 || !strings.Contains(raw, `"entries":null`) && !strings.Contains(raw, `"entries":[]`) {
		t.Fatal("dry run spent", raw)
	}
	// a per-call --max below the price is refused before any signature
	if c, o, _ := run(t, home, env, "pay", srv.URL+"/x", "--max", "0.01"); c != 3 || o.Error.Code != "no_acceptable_offer" {
		t.Fatal("max", c, o)
	}
	// real payment
	c, _, raw = run(t, home, env, "pay", srv.URL+"/x", "--idempotency-key", "k1", "--max", "0.05")
	if c != 0 || !strings.Contains(raw, `"body":{"data":42}`) || !strings.Contains(raw, `"0xfeed"`) {
		t.Fatal(c, raw)
	}
	// same key again: refused, no second payment
	if c, o, _ := run(t, home, env, "pay", srv.URL+"/x", "--idempotency-key", "k1"); c != 4 || o.Error.Code != "already_paid" {
		t.Fatal("idempotency", c, o)
	}
	// policy: lowering needs no secret beyond the admin passphrase; without it the change is refused
	if c, o, _ := run(t, home, map[string]string{"AGPAY_PASSPHRASE_FILE": pf}, "policy", "set", "--max-payment", "0.01"); c != 6 || o.Error.Code != "admin_passphrase_required" {
		t.Fatal("policy without admin", c, o)
	}
	if c, o, _ := run(t, home, env, "policy", "set", "--max-payment", "0.01"); c != 0 {
		t.Fatal("policy set", c, o)
	}
	if c, o, _ := run(t, home, env, "pay", srv.URL+"/x"); c != 3 {
		t.Fatal("new limit not enforced", c, o)
	}
	// tampering with the signed file is detected and blocks spending (fails closed)
	pol := filepath.Join(home, "policy.json")
	b, _ := os.ReadFile(pol)
	os.WriteFile(pol, []byte(strings.Replace(string(b), `"max_payment_atomic": "10000"`, `"max_payment_atomic": "99000000"`, 1)), 0o600)
	if c, o, _ := run(t, home, env, "pay", srv.URL+"/x"); c != 3 || o.Error.Code != "policy_invalid" {
		t.Fatal("tamper", c, o)
	}
	// daily accounting shows the single payment
	os.WriteFile(pol, b, 0o600)
	if c, _, raw := run(t, home, env, "history"); c != 0 || !strings.Contains(raw, `"counted_usdc":"0.031665"`) {
		t.Fatal(raw)
	}
}

func TestPlainHTTPToRemoteHostRefused(t *testing.T) {
	home := filepath.Join(t.TempDir(), "w")
	pf := filepath.Join(t.TempDir(), "pass")
	env := map[string]string{"AGPAY_PASSPHRASE_FILE": pf}
	run(t, home, nil, "init", "--generate-passphrase-file", pf)
	if c, o, _ := run(t, home, env, "pay", "http://example.com/x"); c != 3 || o.Error.Code != "insecure_url" {
		t.Fatal(c, o)
	}
}

func newWallet(t *testing.T, admin bool) (home string, env map[string]string) {
	home = filepath.Join(t.TempDir(), "w")
	pf := filepath.Join(t.TempDir(), "pass")
	af := filepath.Join(t.TempDir(), "admin")
	env = map[string]string{"AGPAY_PASSPHRASE_FILE": pf}
	args := []string{"init", "--generate-passphrase-file", pf}
	if admin {
		args = append(args, "--generate-admin-passphrase-file", af)
	}
	if c, o, raw := run(t, home, nil, args...); c != 0 {
		t.Fatal(c, o, raw)
	}
	return home, env
}

func TestSecretFilesMustBePrivate(t *testing.T) {
	home, env := newWallet(t, false)
	pf := env["AGPAY_PASSPHRASE_FILE"]
	os.Chmod(pf, 0o644)
	if c, o, _ := run(t, home, env, "history"); c != 0 { // history works without the passphrase
		t.Fatal(c, o)
	}
	if c, o, _ := run(t, home, env, "sign-message", "--message", "x"); c != 6 || o.Error.Code != "unsafe_file" {
		t.Fatal("world-readable passphrase file accepted", c, o)
	}
	os.Chmod(pf, 0o600)
	os.Chmod(filepath.Join(home, "wallet.json"), 0o644)
	if c, o, _ := run(t, home, env, "sign-message", "--message", "x"); c != 6 || o.Error.Code != "unsafe_file" {
		t.Fatal("world-readable wallet accepted", c, o)
	}
	os.Chmod(filepath.Join(home, "wallet.json"), 0o600)
	if c, o, _ := run(t, home, env, "sign-message", "--message", "x"); c != 0 {
		t.Fatal(c, o)
	}
	// a symlinked passphrase file is refused
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(pf, link)
	if c, o, _ := run(t, home, map[string]string{"AGPAY_PASSPHRASE_FILE": link}, "sign-message", "--message", "x"); c != 6 || o.Error.Code != "unsafe_file" {
		t.Fatal("symlink accepted", c, o)
	}
}

func TestExportAndRotateNeedAdmin(t *testing.T) {
	home, env := newWallet(t, true)
	if c, o, _ := run(t, home, env, "export", "--i-understand"); c != 6 || o.Error.Code != "admin_passphrase_required" {
		t.Fatal("export without admin", c, o)
	}
	if c, o, _ := run(t, home, env, "export"); c != 2 {
		t.Fatal("export without confirmation", c, o)
	}
	if c, o, _ := run(t, home, env, "rotate-passphrase", "--generate-passphrase-file", filepath.Join(t.TempDir(), "n")); c != 6 || o.Error.Code != "admin_passphrase_required" {
		t.Fatal("rotate without admin", c, o)
	}
}

func TestPolicyRollbackAndTransplantRefused(t *testing.T) {
	mk := func() (string, map[string]string) {
		d := t.TempDir()
		pf, adm := filepath.Join(d, "pass"), filepath.Join(d, "admin")
		env := map[string]string{"AGPAY_PASSPHRASE_FILE": pf, "AGPAY_ADMIN_PASSPHRASE_FILE": adm}
		home := filepath.Join(d, "home")
		if c, o, _ := run(t, home, nil, "init", "--generate-passphrase-file", pf, "--generate-admin-passphrase-file", adm); c != 0 {
			t.Fatal(c, o)
		}
		return home, env
	}
	home, env := mk()
	other, _ := mk()
	pol := filepath.Join(home, "policy.json")
	loose, _ := os.ReadFile(pol)
	if c, o, _ := run(t, home, env, "policy", "set", "--max-payment", "0.5"); c != 0 {
		t.Fatal(c, o)
	}
	// the older, still validly signed policy put back: refused (rollback)
	os.WriteFile(pol, loose, 0o600)
	if c, o, _ := run(t, home, env, "pay", "https://example.com"); c != 3 || o.Error.Code != "policy_invalid" {
		t.Fatal("rollback accepted", c, o)
	}
	// another wallet's validly signed policy: refused (transplant)
	foreign, _ := os.ReadFile(filepath.Join(other, "policy.json"))
	os.WriteFile(pol, foreign, 0o600)
	if c, o, _ := run(t, home, env, "pay", "https://example.com"); c != 3 || o.Error.Code != "policy_invalid" {
		t.Fatal("transplanted policy accepted", c, o)
	}
}

func TestSolanaSignaturesAreEnveloped(t *testing.T) {
	home, env := newWallet(t, false)
	_, o, _ := run(t, home, env, "sign-message", "--chain", "solana", "--message", "hello")
	var r struct {
		Address, Signature string
	}
	json.Unmarshal(o.Result, &r)
	sig, _ := hexDecode(r.Signature)
	pub, _ := b58(r.Address)
	raw := append([]byte("\xffsolana offchain"), 0, 0, 5, 0)
	raw = append(raw, "hello"...)
	if !ed25519Verify(pub, raw, sig) {
		t.Fatal("not the off-chain envelope")
	}
	if ed25519Verify(pub, []byte("hello"), sig) {
		t.Fatal("raw message signature produced")
	}
}

// The seller signature text must equal what the escrow server rebuilds (values from its agpsig package).
func TestEscrowMessageMatchesServer(t *testing.T) {
	var g map[string]string
	b, err := os.ReadFile("../../testdata/agpsig.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &g)
	deal := "dl_0123456789abcdef0123456789abcdef"
	if got := agpMessage("agpay.shveik.dev", deal, "accept", "500000", 1800000000, ""); got != g["accept_text"] {
		t.Fatalf("accept text\n got %q\nwant %q", got, g["accept_text"])
	}
	d := "aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44ee55ff66aa11bb22cc33dd44"
	if got := agpMessage("agpay.shveik.dev", deal, "statement", "500000", 1800000000, d); got != g["stmt_text"] {
		t.Fatalf("statement text\n got %q\nwant %q", got, g["stmt_text"])
	}
	if hexOf(evmPersonal(g["accept_text"])) != g["accept_digest"] {
		t.Fatal("digest differs")
	}
}

func TestMCPServer(t *testing.T) {
	home, env := newWallet(t, false)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"wallet_address","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"pay","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"pay","arguments":{"url":"http://example.com/x"}}}`,
	}, "\n") + "\n"
	var so bytes.Buffer
	Run(&Env{Args: []string{"mcp"}, Home: home, Stdin: strings.NewReader(in), Stdout: &so, Stderr: &bytes.Buffer{}, Getenv: func(k string) string { return env[k] }})
	lines := strings.Split(strings.TrimSpace(so.String()), "\n")
	if len(lines) < 6 {
		t.Fatalf("expected 5 replies, got %d: %s", len(lines), so.String())
	}
	if !strings.Contains(lines[0], `"protocolVersion":"2024-11-05"`) || !strings.Contains(lines[1], `"name":"pay"`) {
		t.Fatal(lines[:2])
	}
	if !strings.Contains(lines[2], `\"evm\":\"0x`) || !strings.Contains(lines[2], `"isError":false`) {
		t.Fatal(lines[2])
	}
	if !strings.Contains(lines[3], `-32602`) {
		t.Fatal("missing argument not rejected:", lines[3])
	}
	if !strings.Contains(lines[4], `"isError":true`) || !strings.Contains(lines[4], `insecure_url`) {
		t.Fatal("policy refusal not surfaced:", lines[4])
	}
}

func TestSendNeedsAllowedDestination(t *testing.T) {
	home, env := newWallet(t, false)
	c, o, _ := run(t, home, env, "send", "--to", "0x1111111111111111111111111111111111111111", "--amount", "0.1", "--network", "base")
	if c != 3 || o.Error.Code != "destination_not_allowed" {
		t.Fatal("send to an unlisted address:", c, o)
	}
}
