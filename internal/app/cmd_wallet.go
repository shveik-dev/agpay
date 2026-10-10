package app

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/sol"
	"github.com/shveik-dev/agpay/internal/vault"
	"github.com/shveik-dev/agpay/internal/x402pay"
)

func init() {
	register(&command{Name: "init", Group: "wallet", Summary: "create the wallet (one seed -> an EVM key and a Solana key), encrypted at rest",
		Example: "agpay init --generate-passphrase-file /run/secrets/agpay.pass",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			gen := fs.String("generate-passphrase-file", "", "write a new random passphrase to this file (0600) and use it")
			adminGen := fs.String("generate-admin-passphrase-file", "", "write a new random admin passphrase to this file (0600); policy changes then need it")
			evmEnv := fs.String("evm-key-env", "", "import: environment variable holding a hex EVM private key")
			solEnv := fs.String("solana-key-env", "", "import: environment variable holding a Solana secret key (base58 keypair or seed, or hex seed)")
			return func(c *ctx) (any, error) {
				if _, err := os.Stat(c.path("wallet.json")); err == nil {
					return nil, walletErr("wallet_exists", "use another --home, or move the old wallet away; init never overwrites", "a wallet already exists in %s", c.Home)
				}
				pass := ""
				var err error
				if *gen != "" {
					if pass, err = writeSecretFile(*gen); err != nil {
						return nil, err
					}
				} else if pass, err = c.passphrase(); err != nil {
					return nil, usage("passphrase_required", "give --generate-passphrase-file, or set AGPAY_PASSPHRASE_FILE / AGPAY_PASSPHRASE before init")
				}
				var s vault.Secrets
				imported := false
				if *evmEnv != "" || *solEnv != "" {
					if *evmEnv == "" || *solEnv == "" {
						return nil, usage("bad_flags", "import needs both --evm-key-env and --solana-key-env")
					}
					ek, err := vault.ParseEVMKey(c.Env.env(*evmEnv))
					if err != nil {
						return nil, usage("bad_key", "%s: %v", *evmEnv, err)
					}
					sk, err := vault.ParseSolanaSecret(c.Env.env(*solEnv))
					if err != nil {
						return nil, usage("bad_key", "%s: %v", *solEnv, err)
					}
					s = vault.Secrets{EVMKey: ek, SolSeed: sk}
					imported = true
				} else {
					seed, err := vault.NewSeed()
					if err != nil {
						return nil, err
					}
					if s, err = vault.Derive(seed); err != nil {
						return nil, err
					}
				}
				var salt []byte
				var adminKey ed25519.PrivateKey
				if *adminGen != "" || c.Pass.admin != "" || c.Env.env("AGPAY_ADMIN_PASSPHRASE") != "" || c.Env.env("AGPAY_ADMIN_PASSPHRASE_FILE") != "" {
					ap := ""
					if *adminGen != "" {
						if ap, err = writeSecretFile(*adminGen); err != nil {
							return nil, err
						}
					} else if ap, err = c.adminPassphrase(); err != nil {
						return nil, err
					}
					salt = policy.NewSalt()
					k, err := policy.AdminKey(ap, salt)
					if err != nil {
						return nil, usage("bad_passphrase", "%v", err)
					}
					s.Admin = hex.EncodeToString(k.Public().(ed25519.PublicKey))
					adminKey = k
				}
				if err := os.MkdirAll(c.Home, 0o700); err != nil {
					return nil, err
				}
				if s.Admin != "" {
					ea, err := evm.AddressOf(hexBytes(s.EVMKey))
					if err != nil {
						return nil, usage("bad_key", "%v", err)
					}
					rules := policy.Defaults()
					rules.Wallet, rules.Seq = ea.Hex(), policy.NextSeq(0)
					s.PolicySeq = rules.Seq
					if err := policy.Save(c.path("policy.json"), rules, adminKey, salt); err != nil {
						return nil, err
					}
				}
				v, err := vault.Create(c.path("wallet.json"), s, pass)
				if err != nil {
					return nil, usage("init_failed", "%v", err)
				}
				return map[string]any{"home": c.Home, "evm_address": v.EVM.Hex(), "solana_address": v.Solana.String(), "imported": imported,
					"admin_policy": s.Admin != "", "next": "fund the addresses with USDC (no gas token is needed to pay: facilitators sponsor gas), then `agpay balance`"}, nil
			}
		}})

	register(&command{Name: "address", Group: "wallet", Summary: "print the wallet's addresses (no passphrase needed)",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			return func(c *ctx) (any, error) {
				e, s, err := vault.Public(c.path("wallet.json"))
				if err != nil {
					return nil, walletErr("no_wallet", "run `agpay init` first", "there is no wallet in %s", c.Home)
				}
				return map[string]any{"evm": e.Hex(), "solana": s.String(),
					"note": "the one EVM address works on every EVM network, including ones added to the policy later"}, nil
			}
		}})

	register(&command{Name: "networks", Group: "wallet", Summary: "list the networks and stablecoins this wallet will pay in",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			return func(c *ctx) (any, error) {
				reg, err := c.registry()
				if err != nil {
					return nil, err
				}
				return map[string]any{"networks": reg.All(), "extend": "add entries to " + c.path("networks.json") + " (caip, kind, usdc, rpc)"}, nil
			}
		}})

	register(&command{Name: "balance", Group: "wallet", Summary: "USDC and gas-token balances on each network",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			network := fs.String("network", "", "only this network (CAIP-2 id or name, e.g. base)")
			testnets := fs.Bool("testnets", false, "include testnets")
			return func(c *ctx) (any, error) {
				ea, sa, err := vault.Public(c.path("wallet.json"))
				if err != nil {
					return nil, walletErr("no_wallet", "run `agpay init` first", "there is no wallet in %s", c.Home)
				}
				reg, err := c.registry()
				if err != nil {
					return nil, err
				}
				var nets []chain.Net
				for _, n := range reg.All() {
					if *network != "" {
						if f, ok := reg.Find(*network); !ok || f.CAIP != n.CAIP {
							continue
						}
					} else if n.Test && !*testnets {
						continue
					}
					nets = append(nets, n)
				}
				if len(nets) == 0 {
					return nil, usage("unknown_network", "no such network: %q (see `agpay networks`)", *network)
				}
				out := make([]map[string]any, len(nets))
				var wg sync.WaitGroup
				for i, n := range nets {
					wg.Add(1)
					go func() {
						defer wg.Done()
						ctx, cancel := contextTimeout(c, 20*time.Second)
						defer cancel()
						row := map[string]any{"network": n.CAIP, "name": n.Name}
						if n.Kind == "evm" {
							row["address"] = ea.Hex()
							rpc := &evm.RPC{URLs: n.RPC}
							tok, _ := evm.ParseAddress(n.USDC)
							if b, err := rpc.BalanceOf(ctx, tok, ea); err != nil {
								row["error"] = err.Error()
							} else {
								row["usdc_atomic"], row["usdc"] = b.String(), n.Format(b)
							}
							if g, err := rpc.NativeBalance(ctx, ea); err == nil {
								row["gas_token"], row["gas_atomic"] = n.Gas, g.String()
							}
						} else {
							row["address"] = sa.String()
							rpc := &sol.RPC{URLs: n.RPC}
							mint, _ := sol.ParseAddress(n.USDC)
							ata, _ := sol.ATA(sa, mint, sol.TokenProgram)
							if b, err := rpc.TokenBalance(ctx, ata); err != nil {
								row["error"] = err.Error()
							} else {
								row["usdc_atomic"], row["usdc"] = b.String(), n.Format(b)
							}
							if l, err := rpc.Lamports(ctx, sa); err == nil {
								row["gas_token"], row["gas_atomic"] = n.Gas, fmt.Sprint(l)
							}
						}
						out[i] = row
					}()
				}
				wg.Wait()
				total := new(big.Int)
				for _, r := range out {
					if s, ok := r["usdc_atomic"].(string); ok {
						if n, ok := new(big.Int).SetString(s, 10); ok {
							total.Add(total, n)
						}
					}
				}
				return map[string]any{"balances": out, "total_usdc": (chain.Net{Decimals: 6}).Format(total)}, nil
			}
		}})

	register(&command{Name: "export", Group: "wallet", Summary: "print the secret keys (for backup or migration); needs --i-understand and, if one was set, the admin passphrase", Secret: true,
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			ok := fs.Bool("i-understand", false, "confirm that the output is a secret that moves all funds")
			return func(c *ctx) (any, error) {
				if !*ok {
					return nil, usage("confirmation_required", "pass --i-understand: this prints private keys")
				}
				v, err := c.openVault()
				if err != nil {
					return nil, err
				}
				if err := c.requireAdmin(v); err != nil {
					return nil, err
				}
				return map[string]any{"seed_hex": v.Secrets.Seed, "evm_key_hex": v.Secrets.EVMKey, "solana_seed_hex": v.Secrets.SolSeed,
					"solana_keypair_base58": sol.B58Encode(v.Secrets.SolKey()),
					"warning":               "anyone holding this controls the funds; never paste it into a prompt or a log"}, nil
			}
		}})

	register(&command{Name: "rotate-passphrase", Group: "wallet", Summary: "re-encrypt the wallet under a new passphrase", Secret: true,
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			newFile := fs.String("new-passphrase-file", "", "file holding the new passphrase")
			gen := fs.String("generate-passphrase-file", "", "write a fresh random passphrase to this file and use it")
			return func(c *ctx) (any, error) {
				v, err := c.openVault()
				if err != nil {
					return nil, err
				}
				if err := c.requireAdmin(v); err != nil {
					return nil, err
				}
				np := ""
				switch {
				case *gen != "":
					np, err = writeSecretFile(*gen)
				case *newFile != "":
					var b []byte
					if b, err = os.ReadFile(*newFile); err == nil {
						np = string(trimNL(b))
					}
				default:
					return nil, usage("bad_flags", "give --new-passphrase-file or --generate-passphrase-file")
				}
				if err != nil {
					return nil, err
				}
				if err := v.Save(np); err != nil {
					return nil, usage("bad_passphrase", "%v", err)
				}
				return map[string]any{"rotated": true}, nil
			}
		}})

	register(&command{Name: "doctor", Group: "wallet", Summary: "check the wallet, passphrase, policy and RPC reachability, with a fix for each problem", Secret: true,
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			return func(c *ctx) (any, error) {
				var checks []map[string]any
				add := func(name string, ok bool, detail, fix string) {
					m := map[string]any{"check": name, "ok": ok, "detail": detail}
					if fix != "" && !ok {
						m["fix"] = fix
					}
					checks = append(checks, m)
				}
				_, _, perr := vault.Public(c.path("wallet.json"))
				add("wallet_file", perr == nil, c.path("wallet.json"), "run `agpay init`")
				if perr != nil {
					return map[string]any{"healthy": false, "checks": checks}, nil
				}
				v, err := c.openVault()
				add("passphrase", err == nil, errText(err), "set AGPAY_PASSPHRASE_FILE to the file written by init")
				healthy := err == nil
				if err == nil {
					r, perr := c.rules(v)
					add("policy", perr == nil, errText(perr), "re-sign the policy with `agpay policy set` and the admin passphrase")
					healthy = healthy && perr == nil
					if perr == nil {
						add("policy_limits", true, fmt.Sprintf("per payment %s, per day %s, per deposit %s USDC", fmtUSD(r.MaxPayment), fmtUSD(r.MaxDay), fmtUSD(r.MaxDeposit)), "")
					}
				}
				reg, rerr := c.registry()
				if rerr == nil {
					for _, n := range reg.All() {
						if n.Test {
							continue
						}
						ctx, cancel := contextTimeout(c, 10*time.Second)
						var e error
						if n.Kind == "evm" {
							_, e = (&evm.RPC{URLs: n.RPC}).Call(ctx, "eth_blockNumber")
						} else {
							_, e = (&sol.RPC{URLs: n.RPC}).Blockhash(ctx)
						}
						cancel()
						add("rpc "+n.CAIP, e == nil, errText(e), "add a working endpoint for it to networks.json")
					}
				}
				if info, err := os.Stat(c.path("wallet.json")); err == nil {
					add("file_mode", info.Mode().Perm()&0o077 == 0, info.Mode().Perm().String(), "chmod 600 "+c.path("wallet.json"))
				}
				for _, ch := range checks {
					if ok, _ := ch["ok"].(bool); !ok {
						healthy = false
					}
				}
				return map[string]any{"healthy": healthy, "checks": checks}, nil
			}
		}})
}

func fmtUSD(atomic string) string {
	n, _ := new(big.Int).SetString(atomic, 10)
	if n == nil {
		return atomic
	}
	return chain.Net{Decimals: 6}.Format(n)
}

func errText(err error) string {
	if err == nil {
		return "ok"
	}
	return err.Error()
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// writeSecretFile writes a fresh 256-bit random passphrase (0600, never overwriting) and returns it.
func writeSecretFile(path string) (string, error) {
	seed, err := vault.NewSeed()
	if err != nil {
		return "", err
	}
	p := hex.EncodeToString(seed)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", usage("secret_file_exists", "cannot create %s: %v", path, err)
	}
	defer f.Close()
	_, err = f.WriteString(p + "\n")
	return p, err
}

var _ = x402pay.ExitUsage

func hexBytes(s string) []byte { b, _ := hex.DecodeString(s); return b }
