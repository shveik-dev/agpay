// Package app is the command line: every command prints exactly one JSON document on stdout,
// never prompts, and ends with a stable exit code, so an agent can drive it without a human.
package app

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/vault"
	"github.com/shveik-dev/agpay/internal/x402pay"
)

var Version = "dev"

// Env is everything a command may touch, so tests can run the CLI in-process.
type Env struct {
	Args   []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	Getenv func(string) string
	Now    func() time.Time
	// Home overrides the data directory (tests).
	Home string
}

type command struct {
	Name    string
	Summary string
	Money   bool // can move or commit funds
	Secret  bool // needs the wallet passphrase
	Example string
	Group   string
	Build   func(fs *flag.FlagSet) func(c *ctx) (any, error)
}

type ctx struct {
	Env    *Env
	Cmd    *command
	Args   []string // positional arguments after the flags
	Ctx    context.Context
	Home   string
	Pass   passFlags
	Pretty bool
}

type passFlags struct{ file, admin string }

func (e *Env) env(k string) string {
	if e.Getenv != nil {
		return e.Getenv(k)
	}
	return os.Getenv(k)
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (c *ctx) path(name string) string { return filepath.Join(c.Home, name) }

// registry is for read-only display; payments use the registry of the verified policy.
func (c *ctx) registry() (*chain.Registry, error) { return c.registryUnverified(), nil }

// usageErr is a wrong invocation (exit 2).
func usage(code, f string, a ...any) *x402pay.Error {
	return &x402pay.Error{Code: code, Message: fmt.Sprintf(f, a...), Exit: x402pay.ExitUsage}
}

func walletErr(code, hint, f string, a ...any) *x402pay.Error {
	return &x402pay.Error{Code: code, Message: fmt.Sprintf(f, a...), Hint: hint, Exit: x402pay.ExitWallet}
}

// readSecret reads a passphrase from, in order: the flag's file, the environment file variable,
// the environment variable itself. It never prompts.
func (c *ctx) readSecret(file, fileEnv, valEnv string) (string, error) {
	read := func(p string) (string, error) {
		if err := checkPrivate(p, "secret file"); err != nil {
			return "", err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	if file != "" {
		return read(file)
	}
	if p := c.Env.env(fileEnv); p != "" {
		return read(p)
	}
	v := c.Env.env(valEnv)
	if v != "" && c.Env.Getenv == nil {
		os.Unsetenv(valEnv) // keep it out of children and later reads of the environment
	}
	return v, nil
}

func (c *ctx) passphrase() (string, error) {
	p, err := c.readSecret(c.Pass.file, "AGPAY_PASSPHRASE_FILE", "AGPAY_PASSPHRASE")
	if err != nil {
		if pe, ok := err.(*x402pay.Error); ok {
			return "", pe
		}
		return "", walletErr("passphrase_unreadable", "", "%v", err)
	}
	if p == "" {
		return "", walletErr("passphrase_required", "set AGPAY_PASSPHRASE_FILE (preferred) or AGPAY_PASSPHRASE, or pass --passphrase-file", "no wallet passphrase was given")
	}
	return p, nil
}

func (c *ctx) adminPassphrase() (string, error) {
	p, err := c.readSecret(c.Pass.admin, "AGPAY_ADMIN_PASSPHRASE_FILE", "AGPAY_ADMIN_PASSPHRASE")
	if err != nil {
		if pe, ok := err.(*x402pay.Error); ok {
			return "", pe
		}
		return "", walletErr("passphrase_unreadable", "", "%v", err)
	}
	if p == "" {
		return "", walletErr("admin_passphrase_required", "set AGPAY_ADMIN_PASSPHRASE_FILE or pass --admin-passphrase-file; only the wallet's owner holds it", "this change needs the admin passphrase")
	}
	return p, nil
}

func (c *ctx) openVault() (*vault.Vault, error) {
	if _, err := os.Stat(c.path("wallet.json")); err != nil {
		return nil, walletErr("no_wallet", "run `agpay init` first", "there is no wallet in %s", c.Home)
	}
	if err := checkHome(c.Home); err != nil {
		return nil, err
	}
	if err := checkPrivate(c.path("wallet.json"), "the wallet file"); err != nil {
		return nil, err
	}
	p, err := c.passphrase()
	if err != nil {
		return nil, err
	}
	v, err := vault.Open(c.path("wallet.json"), p)
	if err != nil {
		if errors.Is(err, vault.ErrWrongPassphrase) {
			return nil, walletErr("wrong_passphrase", "check AGPAY_PASSPHRASE_FILE", "%v", err)
		}
		return nil, walletErr("wallet_unreadable", "", "%v", err)
	}
	return v, nil
}

// rules loads the effective spending rules and checks them against the wallet: a valid admin
// signature (when an admin key is set), this wallet's address, and a sequence number not below the
// last one this wallet accepted (so an old, looser signed policy cannot be put back).
func (c *ctx) rules(v *vault.Vault) (policy.Rules, error) {
	bad := func(f string, a ...any) error {
		return &x402pay.Error{Code: "policy_invalid", Message: fmt.Sprintf(f, a...), Hint: "restore the policy file or re-sign it with `agpay policy set` and the admin passphrase", Exit: x402pay.ExitPolicy}
	}
	if err := checkPrivate(c.path("policy.json"), "the policy file"); err != nil && !os.IsNotExist(err) {
		return policy.Rules{}, err
	}
	r, _, err := policy.Load(c.path("policy.json"), v.Secrets.Admin)
	if err != nil {
		return r, bad("%v", err)
	}
	if v.Secrets.Admin != "" {
		if r.Wallet != v.EVM.Hex() {
			return r, bad("the policy was written for another wallet")
		}
		if r.Seq < v.Secrets.PolicySeq {
			return r, bad("the policy is older than the last one this wallet accepted (rollback)")
		}
	}
	return r, nil
}

func (c *ctx) client() (*x402pay.Client, *vault.Vault, error) {
	v, err := c.openVault()
	if err != nil {
		return nil, nil, err
	}
	rules, err := c.rules(v)
	if err != nil {
		return nil, nil, err
	}
	reg, err := chain.WithExtra(rules.Extra)
	if err != nil {
		return nil, nil, usage("bad_networks", "%v", err)
	}
	for _, p := range []string{"spend.jsonl", "channels.json", "deals.json"} {
		if err := checkPrivate(c.path(p), p); err != nil && !os.IsNotExist(err) {
			return nil, nil, err
		}
	}
	cl := &x402pay.Client{
		Keys:     x402pay.Keys{EVM: v.Secrets.EVMPriv(), EVMAdr: v.EVM, Sol: v.Secrets.SolKey(), SolAdr: v.Solana},
		Reg:      reg,
		Rules:    rules,
		Ledger:   policy.Ledger{Path: c.path("spend.jsonl"), Key: ledgerKey(v)},
		Sessions: x402pay.Store{Path: c.path("channels.json")},
		Now:      c.Env.Now,
	}
	return cl, v, nil
}

// requireAdmin proves the caller holds the admin passphrase when the wallet has one; used for the
// operations an agent must not be able to do on its own (export, rotate, policy changes).
func (c *ctx) requireAdmin(v *vault.Vault) error {
	if v.Secrets.Admin == "" {
		return nil
	}
	ap, err := c.adminPassphrase()
	if err != nil {
		return err
	}
	salt, err := adminSalt(c.path("policy.json"))
	if err != nil {
		return walletErr("policy_invalid", "", "%v", err)
	}
	k, err := policy.AdminKey(ap, salt)
	if err != nil {
		return usage("bad_passphrase", "%v", err)
	}
	if hex.EncodeToString(k.Public().(ed25519.PublicKey)) != v.Secrets.Admin {
		return walletErr("wrong_admin_passphrase", "only the wallet's owner has it", "the admin passphrase is wrong")
	}
	return nil
}

// ---- output ----

type errBody struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Hint      string `json:"hint,omitempty"`
	Retryable bool   `json:"retryable"`
	Exit      int    `json:"exit_code"`
}

func (e *Env) emit(pretty bool, v any) {
	var b []byte
	if pretty {
		b, _ = json.MarshalIndent(v, "", "  ")
	} else {
		b, _ = json.Marshal(v)
	}
	fmt.Fprintln(e.Stdout, string(b))
}

// Run executes one command line and returns the process exit code.
func Run(e *Env) int {
	home := e.Home
	args := e.Args
	var pretty bool
	// global flags may precede the command
	for len(args) > 0 && strings.HasPrefix(args[0], "-") && args[0] != "-h" && args[0] != "--help" {
		switch {
		case args[0] == "--pretty":
			pretty = true
			args = args[1:]
		case args[0] == "--home" && len(args) > 1:
			home, args = args[1], args[2:]
		case strings.HasPrefix(args[0], "--home="):
			home, args = strings.TrimPrefix(args[0], "--home="), args[1:]
		default:
			e.emit(pretty, map[string]any{"ok": false, "error": errBody{Code: "bad_flag", Message: "unknown global flag " + args[0], Hint: "global flags: --home DIR, --pretty; run `agpay describe`", Exit: 2}})
			return 2
		}
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		e.emit(pretty, map[string]any{"ok": true, "command": "help", "result": helpDoc()})
		return 0
	}
	if home == "" {
		home = e.env("AGPAY_HOME")
	}
	if home == "" {
		h, _ := os.UserHomeDir()
		home = filepath.Join(h, ".agpay")
	}
	cmd := find(args[0])
	if cmd == nil {
		e.emit(pretty, map[string]any{"ok": false, "error": errBody{Code: "unknown_command", Message: "no command " + args[0], Hint: "run `agpay describe` for every command and flag", Exit: 2}})
		return 2
	}
	fs := flag.NewFlagSet(cmd.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	c := &ctx{Env: e, Cmd: cmd, Home: home, Pretty: pretty, Ctx: context.Background()}
	fs.StringVar(&c.Pass.file, "passphrase-file", "", "file holding the wallet passphrase (default: $AGPAY_PASSPHRASE_FILE or $AGPAY_PASSPHRASE)")
	fs.StringVar(&c.Pass.admin, "admin-passphrase-file", "", "file holding the admin passphrase (default: $AGPAY_ADMIN_PASSPHRASE_FILE or $AGPAY_ADMIN_PASSPHRASE)")
	fs.BoolVar(&c.Pretty, "pretty", pretty, "indent the JSON output")
	run := cmd.Build(fs)
	if err := fs.Parse(reorder(fs, args[1:])); err != nil {
		return e.fail(c, usage("bad_flags", "%v", err))
	}
	c.Args = fs.Args()
	out, err := run(c)
	if err != nil {
		return e.fail(c, err)
	}
	e.emit(c.Pretty, map[string]any{"ok": true, "command": cmd.Name, "result": out})
	return 0
}

func (e *Env) fail(c *ctx, err error) int {
	var pe *x402pay.Error
	if !errors.As(err, &pe) {
		pe = &x402pay.Error{Code: "error", Message: err.Error(), Exit: 1}
	}
	body := map[string]any{"ok": false, "command": c.Cmd.Name, "error": errBody{pe.Code, pe.Message, pe.Hint, pe.Retryable, pe.Exit}}
	if r, ok := err.(interface{ Detail() any }); ok {
		body["detail"] = r.Detail()
	}
	e.emit(c.Pretty, body)
	return pe.Exit
}

// reorder lets flags follow positional arguments (`pay URL --max 1`), which Go's flag package
// would otherwise treat as the end of the flags.
func reorder(fs *flag.FlagSet, args []string) []string {
	isBool := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) {
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			isBool[f.Name] = true
		}
	})
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			rest = append(rest, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if !strings.Contains(name, "=") && !isBool[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		rest = append(rest, a)
	}
	return append(flags, rest...)
}

var registry []*command

func register(c *command) { registry = append(registry, c) }

func find(name string) *command {
	for _, c := range registry {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func helpDoc() map[string]any {
	var cs []map[string]string
	list := append([]*command(nil), registry...)
	sort.SliceStable(list, func(i, j int) bool { return list[i].Group < list[j].Group })
	for _, c := range list {
		cs = append(cs, map[string]string{"name": c.Name, "group": c.Group, "summary": c.Summary})
	}
	return map[string]any{"name": "agpay", "version": Version, "usage": "agpay [--home DIR] [--pretty] COMMAND [flags] [args]",
		"output": "one JSON document on stdout: {\"ok\":true,\"result\":...} or {\"ok\":false,\"error\":{code,message,hint,retryable,exit_code}}",
		"more":   "agpay describe prints every command, flag, error code and exit code as JSON", "commands": cs}
}

var exitCodes = map[string]string{
	"0": "ok", "1": "unexpected error", "2": "usage: bad command or flags", "3": "refused by the spending policy",
	"4": "payment failed or was rejected", "5": "insufficient funds", "6": "wallet missing or passphrase wrong", "7": "network error (see retryable)",
}
