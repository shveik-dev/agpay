// Package x402pay is a from-scratch x402 client: it reads a 402, picks an offer the owner's rules
// allow, signs it (exact on EVM and Solana, batch-settlement channels on EVM) and replays the
// request with the payment attached. Spec: github.com/x402-foundation/x402 /specs.
package x402pay

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"

	"github.com/shveik-dev/agpay/internal/chain"
)

// Offer is one entry of `accepts`, normalised to the v2 field names.
type Offer struct {
	Raw     map[string]any // as received, echoed back in `accepted`
	Scheme  string
	Network string // CAIP-2
	Amount  *big.Int
	Asset   string
	PayTo   string
	Timeout int64
	Extra   map[string]any
	Net     chain.Net
}

type Required struct {
	Version    int
	Error      string
	Accepts    []map[string]any
	Resource   any
	Extensions any
	// V1 marks a legacy 402 (JSON body, X-PAYMENT header, network names instead of CAIP-2).
	V1 bool
}

// ParseRequired reads the PAYMENT-REQUIRED header (v2) or the JSON body (v1 and old servers).
func ParseRequired(h http.Header, body []byte) (*Required, error) {
	var raw []byte
	if v := h.Get("PAYMENT-REQUIRED"); v != "" {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
		if err != nil {
			return nil, errors.New("PAYMENT-REQUIRED is not valid base64")
		}
		raw = b
	} else {
		raw = body
	}
	var p struct {
		X402Version int              `json:"x402Version"`
		Error       string           `json:"error"`
		Accepts     []map[string]any `json:"accepts"`
		Resource    any              `json:"resource"`
		Extensions  any              `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || len(p.Accepts) == 0 {
		return nil, errors.New("the 402 carries no readable x402 payment requirements")
	}
	r := &Required{Version: p.X402Version, Error: p.Error, Accepts: p.Accepts, Resource: p.Resource, Extensions: p.Extensions}
	if r.Version == 0 {
		r.Version = 1
	}
	r.V1 = r.Version == 1
	return r, nil
}

func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprint(int64(v))
	}
	return ""
}

func num(m map[string]any, k string) int64 {
	switch v := m[k].(type) {
	case float64:
		return int64(v)
	case string:
		n, _ := new(big.Int).SetString(v, 10)
		if n != nil {
			return n.Int64()
		}
	}
	return 0
}

// Normalise turns each accepts entry into an Offer, dropping (with a reason) the ones the wallet
// cannot or must not pay: unknown network, an asset that is not that network's USDC.
func (r *Required) Offers(reg *chain.Registry) (ok []Offer, skipped []string) {
	for _, a := range r.Accepts {
		o := Offer{Raw: a, Scheme: str(a, "scheme"), Network: str(a, "network"), Asset: str(a, "asset"), PayTo: str(a, "payTo"), Timeout: num(a, "maxTimeoutSeconds")}
		o.Extra, _ = a["extra"].(map[string]any)
		amt := str(a, "amount")
		if amt == "" {
			amt = str(a, "maxAmountRequired") // v1
		}
		var good bool
		if o.Amount, good = new(big.Int).SetString(amt, 10); !good || o.Amount.Sign() < 0 || strings.HasPrefix(amt, "+") {
			skipped = append(skipped, fmt.Sprintf("%s/%s: unreadable amount", o.Scheme, o.Network))
			continue
		}
		n, found := reg.Find(o.Network)
		if !found {
			skipped = append(skipped, fmt.Sprintf("%s/%s: network not supported by this wallet", o.Scheme, o.Network))
			continue
		}
		if !n.IsAsset(o.Asset) {
			skipped = append(skipped, fmt.Sprintf("%s/%s: asset %s is not %s's USDC", o.Scheme, o.Network, o.Asset, n.Name))
			continue
		}
		if o.Scheme != "exact" && o.Scheme != "batch-settlement" {
			skipped = append(skipped, fmt.Sprintf("%s/%s: scheme not supported", o.Scheme, o.Network))
			continue
		}
		o.Net = n
		o.Network = n.CAIP
		ok = append(ok, o)
	}
	return
}

// SettleResponse is the decoded PAYMENT-RESPONSE.
type SettleResponse struct {
	Success     bool           `json:"success"`
	ErrorReason string         `json:"errorReason,omitempty"`
	Transaction string         `json:"transaction,omitempty"`
	Network     string         `json:"network,omitempty"`
	Payer       string         `json:"payer,omitempty"`
	Amount      string         `json:"amount,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
}

func ParseSettle(h http.Header) *SettleResponse {
	v := h.Get("PAYMENT-RESPONSE")
	if v == "" {
		v = h.Get("X-PAYMENT-RESPONSE")
	}
	if v == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return nil
	}
	var s SettleResponse
	if json.Unmarshal(b, &s) != nil {
		return nil
	}
	return &s
}
