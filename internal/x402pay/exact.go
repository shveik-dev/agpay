package x402pay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/sol"
)

// Keys are the signing keys, held in memory only while a payment is built.
type Keys struct {
	EVM    []byte
	EVMAdr evm.Address
	Sol    ed25519.PrivateKey
	SolAdr sol.Address
}

func randHex(n int) string { b := make([]byte, n); rand.Read(b); return "0x" + hex.EncodeToString(b) }

func tokenDomain(o Offer) (evm.Domain, error) {
	name, _ := o.Extra["name"].(string)
	version, _ := o.Extra["version"].(string)
	if name == "" || version == "" {
		return evm.Domain{}, errors.New("the offer carries no token EIP-712 name and version (extra.name, extra.version)")
	}
	asset, err := evm.ParseAddress(o.Asset)
	if err != nil {
		return evm.Domain{}, err
	}
	return evm.Domain{Name: name, Version: version, ChainID: big.NewInt(o.Net.ChainID), Contract: asset}, nil
}

// validity returns the EIP-3009 window: valid from ten minutes ago (clock skew), until the offer's
// own timeout (less a margin) from now.
// maxValidity bounds how long a signed authorization stays redeemable, whatever the server asks.
const maxValidity = 600

func validity(o Offer, now time.Time) (after, before int64) {
	t := o.Timeout
	if t <= 0 {
		t = 60
	}
	if t > 40 {
		t -= 10
	}
	if t > maxValidity { // a server must not be able to ask for a long-lived authorization
		t = maxValidity
	}
	return now.Unix() - 600, now.Unix() + t
}

// ExactEVM builds the `exact` payload for an EIP-3009 transferWithAuthorization. The only
// asset transfer method this builder speaks is eip3009 (the default).
func ExactEVM(k Keys, o Offer, now time.Time) (payload map[string]any, validBefore int64, err error) {
	if m, _ := o.Extra["assetTransferMethod"].(string); m != "" && m != "eip3009" {
		return nil, 0, fmt.Errorf("unsupported assetTransferMethod %q (this wallet signs eip3009)", m)
	}
	dom, err := tokenDomain(o)
	if err != nil {
		return nil, 0, err
	}
	to, err := evm.ParseAddress(o.PayTo)
	if err != nil {
		return nil, 0, err
	}
	var nonce [32]byte
	rand.Read(nonce[:])
	after, before := validity(o, now)
	auth := evm.Auth{From: k.EVMAdr, To: to, Value: o.Amount, ValidAfter: big.NewInt(after), Until: big.NewInt(before), Nonce: nonce}
	sig, err := evm.SignEth(k.EVM, evm.AuthDigest(dom, auth))
	if err != nil {
		return nil, 0, err
	}
	return map[string]any{
		"signature": "0x" + hex.EncodeToString(sig),
		"authorization": map[string]any{
			"from": k.EVMAdr.Hex(), "to": to.Hex(), "value": o.Amount.String(),
			"validAfter": fmt.Sprint(after), "validBefore": fmt.Sprint(before), "nonce": "0x" + hex.EncodeToString(nonce[:]),
		},
	}, before, nil
}

const (
	svmComputeUnits = 50_000
	svmUnitPrice    = 1 // micro-lamports per unit: a 1 lamport priority fee, far under every facilitator cap
)

// ExactSVM builds the `exact` payload for Solana: a v0 transaction of ComputeBudget limit, price,
// SPL TransferChecked and one Memo, fee payer = extra.feePayer, signed by us only (the facilitator
// adds the fee payer's signature when it settles).
func ExactSVM(ctx context.Context, rpc *sol.RPC, k Keys, o Offer) (map[string]any, error) {
	feePayerS, _ := o.Extra["feePayer"].(string)
	feePayer, err := sol.ParseAddress(feePayerS)
	if err != nil {
		return nil, errors.New("the offer carries no extra.feePayer")
	}
	mint, err := sol.ParseAddress(o.Asset)
	if err != nil {
		return nil, err
	}
	payTo, err := sol.ParseAddress(o.PayTo)
	if err != nil {
		return nil, err
	}
	if !o.Amount.IsUint64() {
		return nil, errors.New("amount does not fit a token amount")
	}
	owner, exists, err := rpc.AccountOwner(ctx, mint)
	if err != nil {
		return nil, fmt.Errorf("reading the mint: %w", err)
	}
	if !exists || (owner != sol.TokenProgram && owner != sol.Token2022Program) {
		return nil, errors.New("the asset is not an SPL token mint")
	}
	src, err := sol.ATA(k.SolAdr, mint, owner)
	if err != nil {
		return nil, err
	}
	dst, err := sol.ATA(payTo, mint, owner)
	if err != nil {
		return nil, err
	}
	if _, ok, err := rpc.AccountOwner(ctx, dst); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("the merchant has no token account for this asset yet, so a standard exact payment cannot land")
	}
	bal, err := rpc.TokenBalance(ctx, src)
	if err != nil {
		return nil, err
	}
	if bal.Cmp(o.Amount) < 0 {
		return nil, fmt.Errorf("insufficient_funds: the wallet holds %s atomic USDC on %s, the offer needs %s", bal, o.Net.Name, o.Amount)
	}
	bh, err := rpc.Blockhash(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the blockhash: %w", err)
	}
	memo, _ := o.Extra["memo"].(string)
	if memo == "" {
		memo = hex.EncodeToString(randBytes(16))
	}
	if len(memo) > 256 {
		return nil, errors.New("extra.memo is longer than 256 bytes")
	}
	msg := sol.Message(feePayer, []sol.Instruction{
		sol.SetComputeUnitLimit(svmComputeUnits), sol.SetComputeUnitPrice(svmUnitPrice),
		sol.TransferChecked(owner, src, mint, dst, k.SolAdr, o.Amount.Uint64(), uint8(o.Net.Decimals)),
		sol.Memo([]byte(memo)),
	}, bh)
	tx, err := sol.SignedPartial(msg, sol.AccountKeys(msg), k.Sol)
	if err != nil {
		return nil, err
	}
	return map[string]any{"transaction": sol.B64(tx)}, nil
}

func randBytes(n int) []byte { b := make([]byte, n); rand.Read(b); return b }
