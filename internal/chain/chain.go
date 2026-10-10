// Package chain is the registry of networks and stablecoins the wallet will pay in. A 402 that asks
// for any other asset is refused: a server must not be able to name the token it is paid in.
package chain

import (
	"fmt"
	"math/big"
	"strings"
)

type Net struct {
	CAIP     string   `json:"caip"`
	Name     string   `json:"name"`
	V1       string   `json:"v1,omitempty"` // the x402 v1 network name
	Kind     string   `json:"kind"`         // evm | svm
	ChainID  int64    `json:"chain_id,omitempty"`
	USDC     string   `json:"usdc"` // contract address or mint
	Decimals int      `json:"decimals"`
	RPC      []string `json:"rpc"`
	Gas      string   `json:"gas_token"`
	Test     bool     `json:"testnet,omitempty"`
}

// Optional lists EVM networks that use the same code path but have not been paid on live, so they
// are not built in: add them with `agpay policy set --add-network-file` (an admin-signed change).
var Optional = []Net{
	{CAIP: "eip155:42161", Name: "Arbitrum One", V1: "arbitrum", Kind: "evm", ChainID: 42161, USDC: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831", Decimals: 6, Gas: "ETH",
		RPC: []string{"https://arb1.arbitrum.io/rpc"}},
	{CAIP: "eip155:10", Name: "Optimism", V1: "optimism", Kind: "evm", ChainID: 10, USDC: "0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85", Decimals: 6, Gas: "ETH",
		RPC: []string{"https://mainnet.optimism.io"}},
	{CAIP: "eip155:1", Name: "Ethereum", V1: "ethereum", Kind: "evm", ChainID: 1, USDC: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", Decimals: 6, Gas: "ETH",
		RPC: []string{"https://ethereum-rpc.publicnode.com"}},
}

var builtin = []Net{
	{CAIP: "eip155:8453", Name: "Base", V1: "base", Kind: "evm", ChainID: 8453, USDC: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Decimals: 6, Gas: "ETH",
		RPC: []string{"https://mainnet.base.org", "https://base-rpc.publicnode.com"}},
	{CAIP: "eip155:84532", Name: "Base Sepolia", V1: "base-sepolia", Kind: "evm", ChainID: 84532, USDC: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", Decimals: 6, Gas: "ETH", Test: true,
		RPC: []string{"https://sepolia.base.org"}},
	{CAIP: "eip155:137", Name: "Polygon", V1: "polygon", Kind: "evm", ChainID: 137, USDC: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359", Decimals: 6, Gas: "POL",
		RPC: []string{"https://polygon-rpc.com", "https://polygon-bor-rpc.publicnode.com"}},
	{CAIP: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", Name: "Solana", V1: "solana", Kind: "svm", USDC: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", Decimals: 6, Gas: "SOL",
		RPC: []string{"https://api.mainnet-beta.solana.com"}},
	{CAIP: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1", Name: "Solana Devnet", V1: "solana-devnet", Kind: "svm", USDC: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU", Decimals: 6, Gas: "SOL", Test: true,
		RPC: []string{"https://api.devnet.solana.com"}},
}

// Registry is the built-in networks plus any the owner added through the signed policy.
type Registry struct{ nets []Net }

// WithExtra adds owner-defined networks to the built-in ones, validating each.
func WithExtra(extra []Net) (*Registry, error) {
	r := &Registry{nets: append([]Net(nil), builtin...)}
	for _, n := range extra {
		if n.CAIP == "" || n.USDC == "" || (n.Kind != "evm" && n.Kind != "svm") || len(n.RPC) == 0 {
			return nil, fmt.Errorf("a network needs caip, kind (evm|svm), usdc and rpc")
		}
		for _, u := range n.RPC {
			if !strings.HasPrefix(u, "https://") {
				return nil, fmt.Errorf("network %s: rpc endpoints must be https", n.CAIP)
			}
		}
		if n.Decimals == 0 {
			n.Decimals = 6
		}
		if n.Kind == "evm" && n.ChainID == 0 {
			if _, err := fmt.Sscanf(n.CAIP, "eip155:%d", &n.ChainID); err != nil {
				return nil, fmt.Errorf("%s is not an eip155 id", n.CAIP)
			}
		}
		if _, dup := (&Registry{nets: r.nets}).Find(n.CAIP); dup {
			return nil, fmt.Errorf("network %s is already defined", n.CAIP)
		}
		r.nets = append(r.nets, n)
	}
	return r, nil
}

// Builtin is the registry without extras.
func Builtin() *Registry { r, _ := WithExtra(nil); return r }

func (r *Registry) All() []Net { return r.nets }

// Find accepts a CAIP-2 id or an x402 v1 network name.
func (r *Registry) Find(id string) (Net, bool) {
	for _, n := range r.nets {
		if n.CAIP == id || (n.V1 != "" && n.V1 == id) {
			return n, true
		}
	}
	return Net{}, false
}

// IsAsset reports whether asset is this network's registered USDC.
func (n Net) IsAsset(asset string) bool {
	if n.Kind == "evm" {
		return strings.EqualFold(asset, n.USDC)
	}
	return asset == n.USDC
}

// Format renders atomic units as a decimal string.
func (n Net) Format(atomic *big.Int) string {
	s := atomic.String()
	d := n.Decimals
	if d == 0 {
		return s
	}
	for len(s) <= d {
		s = "0" + s
	}
	whole, frac := s[:len(s)-d], strings.TrimRight(s[len(s)-d:], "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// ParseUSD turns a decimal dollar amount ("1.25") into atomic units of a 6-decimal stablecoin.
func ParseUSD(s string) (*big.Int, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "$")
	whole, frac, _ := strings.Cut(s, ".")
	if whole == "" && frac == "" || len(frac) > 6 || strings.ContainsAny(s, "-+eE ") {
		return nil, fmt.Errorf("not a dollar amount with at most 6 decimals: %q", s)
	}
	frac += strings.Repeat("0", 6-len(frac))
	n, ok := new(big.Int).SetString(whole+frac, 10)
	if !ok {
		return nil, fmt.Errorf("not a dollar amount: %q", s)
	}
	return n, nil
}

// New builds a registry from the given networks (tests, embedding).
func New(nets ...Net) *Registry { return &Registry{nets: nets} }
