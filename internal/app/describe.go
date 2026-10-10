package app

import (
	"flag"
	"io"
	"sort"
)

func init() {
	register(&command{Name: "describe", Group: "meta", Summary: "machine-readable description of every command, flag, error code and exit code",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			return func(c *ctx) (any, error) {
				var cmds []map[string]any
				list := append([]*command(nil), registry...)
				sort.SliceStable(list, func(i, j int) bool { return list[i].Name < list[j].Name })
				for _, cm := range list {
					f := flag.NewFlagSet(cm.Name, flag.ContinueOnError)
					f.SetOutput(io.Discard)
					cm.Build(f)
					var flags []map[string]any
					f.VisitAll(func(fl *flag.Flag) {
						kind := "string"
						if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
							kind = "bool"
						}
						flags = append(flags, map[string]any{"name": fl.Name, "type": kind, "default": fl.DefValue, "description": fl.Usage})
					})
					cmds = append(cmds, map[string]any{"name": cm.Name, "group": cm.Group, "summary": cm.Summary, "moves_money": cm.Money,
						"needs_wallet_passphrase": cm.Secret, "example": cm.Example, "flags": flags})
				}
				return map[string]any{
					"name": "agpay", "version": Version,
					"output":     "every command prints exactly one JSON object on stdout: {ok:true,command,result} or {ok:false,command,error:{code,message,hint,retryable,exit_code}[,detail]}",
					"input":      "never prompts; secrets come from files or environment variables only",
					"global":     []string{"--home DIR (or $AGPAY_HOME, default ~/.agpay)", "--pretty"},
					"env":        map[string]string{"AGPAY_HOME": "data directory", "AGPAY_PASSPHRASE_FILE": "file with the wallet passphrase", "AGPAY_PASSPHRASE": "the passphrase itself (less safe: visible in the process environment)", "AGPAY_ADMIN_PASSPHRASE_FILE": "file with the admin passphrase (policy changes)", "AGPAY_SERVICE_URL": "agpay escrow origin"},
					"exit_codes": exitCodes,
					"error_codes": []string{"no_wallet", "wallet_exists", "passphrase_required", "wrong_passphrase", "policy_invalid", "wrong_admin_passphrase", "admin_passphrase_required",
						"insecure_url", "host_not_allowed", "bad_402", "no_acceptable_offer", "limit_exceeded", "insufficient_funds", "payment_rejected", "payment_unconfirmed",
						"already_paid", "sign_failed", "network_error", "rpc_error", "bad_flags", "bad_args", "unknown_command", "unknown_deal", "confirmation_required"},
					"commands": cmds,
					"safety": []string{"payments are only made in each network's registered USDC", "limits (per payment, per day, per channel deposit, hosts, networks) are enforced before any signature",
						"policy changes need the admin passphrase when one was set at init", "use --dry-run or `quote` to see a price without paying", "use --idempotency-key so a retry never pays twice"},
				}, nil
			}
		}})
}
