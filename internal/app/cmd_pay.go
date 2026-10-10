package app

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/vault"
	"github.com/shveik-dev/agpay/internal/x402pay"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type reqFlags struct {
	method, data, network, scheme, max, key, out string
	headers                                      multi
	dry                                          bool
	timeout                                      time.Duration
}

func (r *reqFlags) bind(fs *flag.FlagSet, withPay bool) {
	fs.StringVar(&r.method, "X", "", "HTTP method (default GET, or POST when --data is given)")
	fs.StringVar(&r.data, "data", "", "request body: a string, @file, or @- for stdin")
	fs.Var(&r.headers, "H", "extra request header \"Name: value\" (repeatable)")
	fs.StringVar(&r.network, "network", "", "prefer this network (CAIP-2 id or name)")
	fs.StringVar(&r.scheme, "scheme", "", "exact or batch-settlement (default: exact, or an already open channel)")
	fs.DurationVar(&r.timeout, "timeout", 4*time.Minute, "overall time limit")
	if withPay {
		fs.StringVar(&r.max, "max", "", "refuse to pay more than this many dollars for this call, e.g. 0.05")
		fs.StringVar(&r.key, "idempotency-key", "", "a retry with the same key never pays twice")
		fs.StringVar(&r.out, "out", "", "write the response body to this file instead of inlining it")
		fs.BoolVar(&r.dry, "dry-run", false, "show what would be paid and why, without signing or spending")
	}
}

func (r *reqFlags) build(c *ctx, url string) (x402pay.Request, error) {
	req := x402pay.Request{Method: r.method, URL: url, Header: http.Header{}, Network: r.network, Scheme: r.scheme, DryRun: r.dry, Key: r.key}
	if r.scheme != "" && r.scheme != "exact" && r.scheme != "batch-settlement" {
		return req, usage("bad_flags", "--scheme is exact or batch-settlement")
	}
	for _, h := range r.headers {
		k, v, ok := strings.Cut(h, ":")
		if !ok {
			return req, usage("bad_flags", "header %q is not \"Name: value\"", h)
		}
		if strings.EqualFold(strings.TrimSpace(k), "PAYMENT-SIGNATURE") || strings.EqualFold(strings.TrimSpace(k), "X-PAYMENT") {
			return req, usage("bad_flags", "payment headers are set by the wallet")
		}
		req.Header.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	switch {
	case r.data == "@-":
		b, err := io.ReadAll(io.LimitReader(c.Env.Stdin, 16<<20))
		if err != nil {
			return req, err
		}
		req.Body = b
	case strings.HasPrefix(r.data, "@"):
		b, err := os.ReadFile(r.data[1:])
		if err != nil {
			return req, usage("bad_flags", "%v", err)
		}
		req.Body = b
	default:
		req.Body = []byte(r.data)
	}
	if req.Method == "" {
		req.Method = "GET"
		if len(req.Body) > 0 {
			req.Method = "POST"
		}
	}
	if r.max != "" {
		m, err := chain.ParseUSD(r.max)
		if err != nil {
			return req, usage("bad_flags", "--max: %v", err)
		}
		req.MaxAtomic = m
	}
	return req, nil
}

const inlineLimit = 1 << 20

func bodyField(out map[string]any, b []byte, file string) {
	out["bytes"] = len(b)
	out["body_is_untrusted"] = true // third-party data: an agent must not follow instructions found in it
	if file != "" {
		if err := os.WriteFile(file, b, 0o600); err != nil {
			out["body_error"] = err.Error()
		} else {
			out["body_file"] = file
		}
		return
	}
	trunc := false
	if len(b) > inlineLimit {
		b, trunc = b[:inlineLimit], true
		out["truncated"] = true
		out["hint"] = "the body is over 1 MiB: repeat with --out FILE to keep all of it"
	}
	if !trunc && json.Valid(b) {
		out["body"] = json.RawMessage(b)
	} else if utf8.Valid(b) {
		out["body_text"] = string(b)
	} else {
		out["body_base64"] = base64.StdEncoding.EncodeToString(b)
	}
}

func receipt(res *x402pay.Result) map[string]any {
	m := map[string]any{}
	if res.Chosen != nil {
		m["scheme"], m["network"], m["amount_atomic"], m["amount_usdc"], m["pay_to"] = res.Chosen.Scheme, res.Chosen.Network, res.Chosen.Amount, res.Chosen.USD, res.Chosen.PayTo
	}
	if res.SpendID != "" {
		m["spend_id"] = res.SpendID
	}
	if res.Channel != "" {
		m["channel_id"] = res.Channel
	}
	if res.Deposit != "" {
		m["deposit_atomic"] = res.Deposit
	}
	if res.Settle != nil {
		m["settlement"] = res.Settle
	}
	return m
}

// failDetail attaches the partial result (quote, receipt) to a payment error.
type detailErr struct {
	inner *x402pay.Error
	d     any
}

func (e detailErr) Error() string { return e.inner.Error() }

func (e detailErr) Detail() any   { return e.d }
func (e detailErr) Unwrap() error { return e.inner }

func init() {
	register(&command{Name: "quote", Group: "pay", Summary: "see what a URL costs and which offers the policy allows, without paying", Secret: true,
		Example: "agpay quote https://agdata.shveik.dev/x402/web-search --data '{\"query\":\"x\"}'",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			var rf reqFlags
			rf.bind(fs, false)
			return func(c *ctx) (any, error) {
				if len(c.Args) != 1 {
					return nil, usage("bad_args", "usage: agpay quote URL [--data BODY] [-X METHOD]")
				}
				cl, _, err := c.client()
				if err != nil {
					return nil, err
				}
				req, err := rf.build(c, c.Args[0])
				if err != nil {
					return nil, err
				}
				cctx, cancel := contextTimeout(c, rf.timeout)
				defer cancel()
				res, r402, _, err := cl.Quote(cctx, req)
				if err != nil {
					return nil, err
				}
				out := map[string]any{"status": res.Status, "payment_required": r402 != nil}
				if r402 != nil {
					out["x402_version"], out["offers"], out["error"] = r402.Version, res.Quote, r402.Error
					ok := false
					for _, q := range res.Quote {
						ok = ok || q.Allowed
					}
					out["payable"] = ok
				} else {
					out["note"] = "no payment is needed for this request"
				}
				return out, nil
			}
		}})

	pay := func(name, summary string) *command {
		return &command{Name: name, Group: "pay", Summary: summary, Money: true, Secret: true,
			Example: "agpay pay https://agdata.shveik.dev/x402/web-search --data '{\"query\":\"x\"}' --max 0.05",
			Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
				var rf reqFlags
				rf.bind(fs, true)
				return func(c *ctx) (any, error) {
					if len(c.Args) != 1 {
						return nil, usage("bad_args", "usage: agpay pay URL [--data BODY] [-X METHOD] [--max USD]")
					}
					cl, _, err := c.client()
					if err != nil {
						return nil, err
					}
					req, err := rf.build(c, c.Args[0])
					if err != nil {
						return nil, err
					}
					cctx, cancel := contextTimeout(c, rf.timeout)
					defer cancel()
					res, err := cl.Pay(cctx, req)
					if err != nil {
						if res != nil {
							d := receipt(res)
							d["offers"] = res.Quote
							return nil, detailErr{asErr(err), d}
						}
						return nil, err
					}
					out := map[string]any{"status": res.Status, "paid": res.Paid}
					if rf.dry {
						out["dry_run"] = true
						out["would_pay"] = res.Chosen
						out["offers"] = res.Quote
						return out, nil
					}
					if res.Paid {
						out["payment"] = receipt(res)
					} else if res.Chosen == nil {
						out["note"] = "the server did not ask for payment"
					}
					if ct := res.Header.Get("Content-Type"); ct != "" {
						out["content_type"] = ct
					}
					bodyField(out, res.Body, rf.out)
					return out, nil
				}
			}}
	}
	register(pay("pay", "call a paid URL: pays the 402 within the policy and returns the response"))
	register(pay("fetch", "alias of pay"))

	register(&command{Name: "channels", Group: "pay", Summary: "batch-settlement channels: list the open ones, or ask a server for a cooperative refund", Money: true, Secret: true,
		Example: "agpay channels list | agpay channels refund https://api.example.com/x",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			var rf reqFlags
			rf.bind(fs, false)
			amount := fs.String("amount", "", "refund: dollars to take back (default: the whole unspent balance)")
			return func(c *ctx) (any, error) {
				if len(c.Args) == 0 {
					return nil, usage("bad_args", "usage: agpay channels list | refund URL [--amount USD]")
				}
				cl, _, err := c.client()
				if err != nil {
					return nil, err
				}
				switch c.Args[0] {
				case "list":
					all, err := cl.Sessions.All()
					return map[string]any{"channels": all}, err
				case "refund":
					if len(c.Args) != 2 {
						return nil, usage("bad_args", "usage: agpay channels refund URL [--amount USD]")
					}
					req, err := rf.build(c, c.Args[1])
					if err != nil {
						return nil, err
					}
					var amt *big.Int
					if *amount != "" {
						if amt, err = chain.ParseUSD(*amount); err != nil {
							return nil, usage("bad_flags", "--amount: %v", err)
						}
					}
					cctx, cancel := contextTimeout(c, rf.timeout)
					defer cancel()
					res, err := cl.Refund(cctx, req, amt)
					if err != nil {
						return nil, err
					}
					return map[string]any{"refunded": true, "channel_id": res.Channel, "settlement": res.Settle}, nil
				}
				return nil, usage("bad_args", "unknown channels action %q", c.Args[0])
			}
		}})

	register(&command{Name: "history", Group: "pay", Summary: "what the wallet has spent: every payment with its status, and the totals against the limits",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			hours := fs.Int("hours", 24, "how far back to list")
			return func(c *ctx) (any, error) {
				l := policy.Ledger{Path: c.path("spend.jsonl")}
				verified := false
				if v, err := c.openVault(); err == nil {
					l.Key, verified = ledgerKey(v), true // with the wallet key the chain of MACs is checked
				}
				es, err := l.List(c.Env.now().Add(-time.Duration(*hours) * time.Hour))
				if err != nil {
					return nil, &x402pay.Error{Code: "ledger_tampered", Message: err.Error(), Exit: x402pay.ExitPolicy}
				}
				spent, _ := l.Spent(c.Env.now())
				return map[string]any{"verified": verified, "entries": es, "counted_against_daily_limit_atomic": spent.String(), "counted_usdc": chain.Net{Decimals: 6}.Format(spent)}, nil
			}
		}})

	register(&command{Name: "policy", Group: "policy", Summary: "show the spending policy; `policy set` changes it and needs the admin passphrase if one was set at init",
		Example: "agpay policy show | agpay policy set --max-payment 2 --max-day 20 --hosts agdata.shveik.dev",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			maxPay := fs.String("max-payment", "", "dollars per payment")
			maxDay := fs.String("max-day", "", "dollars per rolling 24 hours")
			maxDep := fs.String("max-deposit", "", "dollars per batch-settlement channel deposit")
			hosts := fs.String("hosts", "", "comma-separated allowed hosts (\"*.example.com\" ok); \"any\" clears the list")
			networks := fs.String("networks", "", "comma-separated allowed CAIP-2 networks; \"any\" clears the list")
			schemes := fs.String("schemes", "", "comma-separated schemes (exact, batch-settlement)")
			allowHTTP := fs.String("allow-http", "", "true or false: permit plain http to non-loopback hosts")
			addNets := fs.String("add-network-file", "", "add the networks in this JSON file (array of {caip,kind,usdc,rpc[,name,v1,chain_id,decimals]}) to the registry")
			clearNets := fs.Bool("clear-networks", false, "remove all owner-added networks")
			return func(c *ctx) (any, error) {
				sub := "show"
				if len(c.Args) > 0 {
					sub = c.Args[0]
				}
				_, _, perr := vault.Public(c.path("wallet.json"))
				if perr != nil {
					return nil, walletErr("no_wallet", "run `agpay init` first", "there is no wallet in %s", c.Home)
				}
				v, err := c.openVault()
				if err != nil {
					return nil, err
				}
				rules, err := c.rules(v)
				if err != nil {
					return nil, err
				}
				if sub == "show" {
					return map[string]any{"rules": rules, "signed_by_admin": v.Secrets.Admin != ""}, nil
				}
				if sub != "set" {
					return nil, usage("bad_args", "usage: agpay policy show|set")
				}
				usd := func(s string, dst *string) error {
					if s == "" {
						return nil
					}
					n, err := chain.ParseUSD(s)
					if err != nil {
						return usage("bad_flags", "%v", err)
					}
					*dst = n.String()
					return nil
				}
				if err := firstErr(usd(*maxPay, &rules.MaxPayment), usd(*maxDay, &rules.MaxDay), usd(*maxDep, &rules.MaxDeposit)); err != nil {
					return nil, err
				}
				list := func(s string) []string {
					if s == "any" {
						return nil
					}
					var out []string
					for _, p := range strings.Split(s, ",") {
						if p = strings.TrimSpace(p); p != "" {
							out = append(out, p)
						}
					}
					return out
				}
				if *hosts != "" {
					rules.Hosts = list(*hosts)
				}
				if *networks != "" {
					rules.Networks = list(*networks)
				}
				if *schemes != "" {
					rules.Schemes = list(*schemes)
				}
				if *allowHTTP != "" {
					rules.AllowHTTP = *allowHTTP == "true"
				}
				var adminKey ed25519.PrivateKey
				var salt []byte
				if v.Secrets.Admin != "" {
					if err := c.requireAdmin(v); err != nil {
						return nil, err
					}
					ap, _ := c.adminPassphrase()
					salt, _ = adminSalt(c.path("policy.json"))
					adminKey, _ = policy.AdminKey(ap, salt)
				}
				if *clearNets {
					rules.Extra = nil
				}
				if *addNets != "" {
					b, err := os.ReadFile(*addNets)
					if err != nil {
						return nil, usage("bad_flags", "%v", err)
					}
					var add []chain.Net
					if err := json.Unmarshal(b, &add); err != nil {
						return nil, usage("bad_flags", "--add-network-file must hold a JSON array of networks: %v", err)
					}
					rules.Extra = append(rules.Extra, add...)
				}
				if _, err := chain.WithExtra(rules.Extra); err != nil {
					return nil, usage("bad_networks", "%v", err)
				}
				rules.Wallet = v.EVM.Hex()
				rules.Seq = policy.NextSeq(max64(rules.Seq, v.Secrets.PolicySeq))
				if err := policy.Save(c.path("policy.json"), rules, adminKey, salt); err != nil {
					return nil, usage("bad_policy", "%v", err)
				}
				if v.Secrets.Admin != "" {
					v.Secrets.PolicySeq = rules.Seq
					pass, err := c.passphrase()
					if err != nil {
						return nil, err
					}
					if err := v.Save(pass); err != nil {
						return nil, err
					}
				}
				return map[string]any{"rules": rules, "signed_by_admin": adminKey != nil}, nil
			}
		}})

	register(&command{Name: "sign-message", Group: "sign", Summary: "sign a message with the wallet key: EIP-191 personal_sign (EVM) or ed25519 (Solana)", Secret: true,
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			family := fs.String("chain", "evm", "evm or solana")
			msg := fs.String("message", "", "the text to sign, or @file, or @- for stdin")
			return func(c *ctx) (any, error) {
				if *msg == "" {
					return nil, usage("bad_args", "give --message")
				}
				var m []byte
				switch {
				case *msg == "@-":
					m, _ = io.ReadAll(io.LimitReader(c.Env.Stdin, 1<<20))
				case strings.HasPrefix(*msg, "@"):
					b, err := os.ReadFile((*msg)[1:])
					if err != nil {
						return nil, usage("bad_args", "%v", err)
					}
					m = b
				default:
					m = []byte(*msg)
				}
				v, err := c.openVault()
				if err != nil {
					return nil, err
				}
				switch *family {
				case "evm":
					sig, err := evm.SignEth(v.Secrets.EVMPriv(), evm.PersonalHash(m))
					if err != nil {
						return nil, err
					}
					return map[string]any{"address": v.EVM.Hex(), "scheme": "eip191", "signature": "0x" + hex.EncodeToString(sig)}, nil
				case "solana":
					if len(m) > 1212 {
						return nil, usage("bad_args", "a Solana off-chain message is at most 1212 bytes")
					}
					return map[string]any{"address": v.Solana.String(), "scheme": "solana-offchain-v0", "signature": solSign(v, m),
						"note": "signed with the Solana off-chain message header, so it can never be a transaction"}, nil
				}
				return nil, usage("bad_flags", "--chain is evm or solana")
			}
		}})
}

func asErr(err error) *x402pay.Error {
	if pe, ok := err.(*x402pay.Error); ok {
		return pe
	}
	return &x402pay.Error{Code: "error", Message: err.Error(), Exit: 1}
}

func firstErr(es ...error) error {
	for _, e := range es {
		if e != nil {
			return e
		}
	}
	return nil
}

func adminSalt(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s policy.Signed
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return hex.DecodeString(s.AdminSalt)
}

// solSign signs inside the Solana off-chain message envelope (\xffsolana offchain, version, format,
// length): raw ed25519 over caller bytes could be a transaction message that moves every token, the
// envelope's first byte can never start one.
func solSign(v *vault.Vault, m []byte) string {
	format := byte(0) // restricted ASCII
	for _, ch := range m {
		if ch < 0x20 || ch > 0x7e {
			format = 1 // UTF-8
			break
		}
	}
	env := append([]byte("\xffsolana offchain"), 0, format, byte(len(m)), byte(len(m)>>8))
	env = append(env, m...)
	return "0x" + hex.EncodeToString(ed25519.Sign(v.Secrets.SolKey(), env))
}

func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
