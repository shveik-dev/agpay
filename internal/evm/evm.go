// Package evm holds the Ethereum-side primitives the wallet needs: keccak, addresses, EIP-191
// and EIP-712 hashing, the EIP-3009 transferWithAuthorization digest and a tiny JSON-RPC client.
package evm

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/shveik-dev/agpay/internal/secp"
)

func Keccak(parts ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

type Address [20]byte

// AddressOf derives the address of a 32-byte private key.
func AddressOf(priv []byte) (Address, error) {
	pub, err := secp.PublicKey(priv)
	if err != nil {
		return Address{}, err
	}
	var a Address
	copy(a[:], Keccak(pub)[12:])
	return a, nil
}

// Hex is the EIP-55 checksummed form.
func (a Address) Hex() string {
	lower := hex.EncodeToString(a[:])
	h := hex.EncodeToString(Keccak([]byte(lower)))
	out := []byte(lower)
	for i, c := range out {
		if c >= 'a' && c <= 'f' && h[i] >= '8' {
			out[i] = c - 32
		}
	}
	return "0x" + string(out)
}

func ParseAddress(s string) (Address, error) {
	var a Address
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		return a, fmt.Errorf("not an EVM address: %q", s)
	}
	copy(a[:], b)
	return a, nil
}

func pad32(b []byte) []byte {
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}

func u256(v *big.Int) []byte { return pad32(v.Bytes()) }

// PersonalHash is the EIP-191 personal_sign digest.
func PersonalHash(msg []byte) []byte {
	return Keccak([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(msg))), msg)
}

// SignEth signs a 32-byte digest and returns the 65-byte r||s||v signature with v in {27,28}.
func SignEth(priv, digest []byte) ([]byte, error) {
	sig, err := secp.Sign(priv, digest)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

// RecoverEth returns the signer of a digest from a 65-byte signature with v in {0,1,27,28}.
func RecoverEth(digest, sig []byte) (Address, error) {
	var a Address
	if len(sig) != 65 {
		return a, errors.New("signature must be 65 bytes")
	}
	s := append([]byte(nil), sig...)
	if s[64] >= 27 {
		s[64] -= 27
	}
	pub, err := secp.Recover(digest, s)
	if err != nil {
		return a, err
	}
	copy(a[:], Keccak(pub)[12:])
	return a, nil
}

// Domain is an EIP-712 domain with the four standard fields.
type Domain struct {
	Name, Version string
	ChainID       *big.Int
	Contract      Address
}

var domainType = Keccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))

func (d Domain) Separator() []byte {
	return Keccak(domainType, Keccak([]byte(d.Name)), Keccak([]byte(d.Version)), u256(d.ChainID), pad32(d.Contract[:]))
}

// TypedDigest is keccak(0x1901 || domainSeparator || structHash).
func TypedDigest(d Domain, structHash []byte) []byte {
	return Keccak([]byte{0x19, 0x01}, d.Separator(), structHash)
}

// Auth is an EIP-3009 TransferWithAuthorization.
type Auth struct {
	From, To                 Address
	Value, ValidAfter, Until *big.Int
	Nonce                    [32]byte
}

var authType = Keccak([]byte("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))

func AuthDigest(d Domain, a Auth) []byte {
	return TypedDigest(d, Keccak(authType, pad32(a.From[:]), pad32(a.To[:]), u256(a.Value), u256(a.ValidAfter), u256(a.Until), a.Nonce[:]))
}

// RPC is a minimal JSON-RPC client that tries each endpoint in turn.
type RPC struct {
	URLs []string
	HTTP *http.Client
}

func (r *RPC) Call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	hc := r.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	var last error
	for _, u := range r.URLs {
		req, _ := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(body))
		req.Header.Set("content-type", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			last = err
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		var out struct {
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(b, &out) != nil {
			last = fmt.Errorf("rpc %s: HTTP %d, not JSON", u, resp.StatusCode)
			continue
		}
		if out.Error != nil {
			last = fmt.Errorf("rpc %s: %s", method, out.Error.Message)
			continue
		}
		return out.Result, nil
	}
	if last == nil {
		last = errors.New("no rpc endpoints")
	}
	return nil, last
}

// BalanceOf reads an ERC-20 balance.
func (r *RPC) BalanceOf(ctx context.Context, token, owner Address) (*big.Int, error) {
	data := append(Keccak([]byte("balanceOf(address)"))[:4], pad32(owner[:])...)
	res, err := r.Call(ctx, "eth_call", map[string]string{"to": token.Hex(), "data": "0x" + hex.EncodeToString(data)}, "latest")
	if err != nil {
		return nil, err
	}
	var s string
	json.Unmarshal(res, &s)
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// NativeBalance reads the chain's gas token balance in wei.
func (r *RPC) NativeBalance(ctx context.Context, owner Address) (*big.Int, error) {
	res, err := r.Call(ctx, "eth_getBalance", owner.Hex(), "latest")
	if err != nil {
		return nil, err
	}
	var s string
	json.Unmarshal(res, &s)
	v, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return nil, errors.New("bad balance")
	}
	return v, nil
}

var _ = bytes.Equal
