package app

import (
	"context"
	"crypto/ed25519"
	"flag"
	"math/big"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/sol"
	"github.com/shveik-dev/agpay/internal/x402pay"
)

func init() {
	register(&command{Name: "send", Group: "wallet", Summary: "send USDC out of the wallet to an address the owner allowed (policy allow_send_to); the wallet pays the network fee", Money: true, Secret: true,
		Example: "agpay send --to 0x... --amount 1.25 --network base",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			to := fs.String("to", "", "destination address (must be in the policy's allow_send_to)")
			amount := fs.String("amount", "", "dollars to send")
			all := fs.Bool("all", false, "send the whole USDC balance on the network")
			network := fs.String("network", "", "network (CAIP-2 id or name)")
			dry := fs.Bool("dry-run", false, "check everything and show what would be sent")
			return func(c *ctx) (any, error) {
				if *to == "" || *network == "" || (*amount == "") == !*all {
					return nil, usage("bad_flags", "give --to, --network and exactly one of --amount or --all")
				}
				cl, v, err := c.client()
				if err != nil {
					return nil, err
				}
				n, ok := cl.Reg.Find(*network)
				if !ok {
					return nil, usage("unknown_network", "no such network: %q", *network)
				}
				if !cl.Rules.NetworkOK(n.CAIP) {
					return nil, &x402pay.Error{Code: "network_not_allowed", Message: "the policy does not allow " + n.Name, Exit: x402pay.ExitPolicy}
				}
				if !cl.Rules.SendOK(*to) {
					return nil, &x402pay.Error{Code: "destination_not_allowed", Message: *to + " is not in the policy's allow_send_to", Hint: "only the owner can add it: `agpay policy set --send-to ADDRESS` with the admin passphrase", Exit: x402pay.ExitPolicy}
				}
				cctx, cancel := contextTimeout(c, 3*time.Minute)
				defer cancel()
				// balance and amount
				var bal *big.Int
				if n.Kind == "evm" {
					dest, err := evm.ParseAddress(*to)
					if err != nil {
						return nil, usage("bad_flags", "--to: %v", err)
					}
					tok, _ := evm.ParseAddress(n.USDC)
					if bal, err = (&evm.RPC{URLs: n.RPC}).BalanceOf(cctx, tok, v.EVM); err != nil {
						return nil, &x402pay.Error{Code: "rpc_error", Message: err.Error(), Exit: x402pay.ExitNetwork, Retryable: true}
					}
					_ = dest
				} else {
					mint, _ := sol.ParseAddress(n.USDC)
					prog := sol.TokenProgram
					src, _ := sol.ATA(v.Solana, mint, prog)
					if bal, err = (&sol.RPC{URLs: n.RPC}).TokenBalance(cctx, src); err != nil {
						return nil, &x402pay.Error{Code: "rpc_error", Message: err.Error(), Exit: x402pay.ExitNetwork, Retryable: true}
					}
				}
				amt := new(big.Int)
				if *all {
					amt.Set(bal)
				} else if amt, err = chain.ParseUSD(*amount); err != nil {
					return nil, usage("bad_flags", "--amount: %v", err)
				}
				if amt.Sign() <= 0 || amt.Cmp(bal) > 0 {
					return nil, &x402pay.Error{Code: "insufficient_funds", Message: "the wallet holds " + n.Format(bal) + " USDC on " + n.Name, Exit: x402pay.ExitFunds}
				}
				out := map[string]any{"network": n.CAIP, "to": *to, "amount_atomic": amt.String(), "amount_usdc": n.Format(amt)}
				if *dry {
					out["dry_run"] = true
					return out, nil
				}
				e := policy.Entry{ID: policy.NewID(), Host: "send", Network: n.CAIP, Scheme: "send", Kind: "send", Amount: amt.String(), Asset: n.USDC, Note: *to, ValidUntil: c.Env.now().Add(5 * time.Minute).Unix()}
				if err := cl.Ledger.Reserve(cl.Rules, e, c.Env.now()); err != nil {
					if le, ok := err.(*policy.LimitError); ok {
						return nil, &x402pay.Error{Code: "limit_exceeded", Message: le.Error(), Hint: "the owner can raise the limits with the admin passphrase", Exit: x402pay.ExitPolicy}
					}
					return nil, &x402pay.Error{Code: "ledger_error", Message: err.Error(), Exit: 1}
				}
				var tx string
				if n.Kind == "evm" {
					tok, _ := evm.ParseAddress(n.USDC)
					dest, _ := evm.ParseAddress(*to)
					data := append(evm.Keccak([]byte("transfer(address,uint256)"))[:4], leftPad(dest[:])...)
					data = append(data, leftPad(amt.Bytes())...)
					tx, err = (&evm.RPC{URLs: n.RPC}).Send(cctx, v.Secrets.EVMPriv(), uint64(n.ChainID), tok, data)
				} else {
					tx, err = solSend(cctx, n, v.Solana, v.Secrets.SolKey(), *to, amt)
				}
				if err != nil {
					cl.Ledger.Finish(e.ID, "failed", tx, err.Error())
					return nil, &x402pay.Error{Code: "send_failed", Message: err.Error(), Hint: "the wallet needs the network's gas token (ETH, POL or SOL) to pay the fee", Exit: x402pay.ExitPayment}
				}
				cl.Ledger.Finish(e.ID, "settled", tx, *to)
				out["transaction"] = tx
				return out, nil
			}
		}})
}

func leftPad(b []byte) []byte { o := make([]byte, 32); copy(o[32-len(b):], b); return o }

func solSend(ctx context.Context, n chain.Net, from sol.Address, key ed25519.PrivateKey, to string, amt *big.Int) (string, error) {
	rpc := &sol.RPC{URLs: n.RPC}
	dest, err := sol.ParseAddress(to)
	if err != nil {
		return "", err
	}
	mint, _ := sol.ParseAddress(n.USDC)
	prog := sol.TokenProgram
	src, _ := sol.ATA(from, mint, prog)
	dstATA, err := sol.ATA(dest, mint, prog)
	if err != nil {
		return "", err
	}
	bh, err := rpc.Blockhash(ctx)
	if err != nil {
		return "", err
	}
	msg := sol.Message(from, []sol.Instruction{
		sol.SetComputeUnitLimit(60_000), sol.SetComputeUnitPrice(1),
		sol.CreateATAIdempotent(from, dstATA, dest, mint, prog),
		sol.TransferChecked(prog, src, mint, dstATA, from, amt.Uint64(), uint8(n.Decimals)),
	}, bh)
	raw, err := sol.SignedPartial(msg, sol.AccountKeys(msg), key)
	if err != nil {
		return "", err
	}
	return rpc.SendTx(ctx, raw)
}
