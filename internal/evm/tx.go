package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

func rlpBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append(rlpLen(len(b), 0x80), b...)
}

func rlpLen(n int, off byte) []byte {
	if n < 56 {
		return []byte{off + byte(n)}
	}
	var l []byte
	for x := n; x > 0; x >>= 8 {
		l = append([]byte{byte(x)}, l...)
	}
	return append([]byte{off + 55 + byte(len(l))}, l...)
}

func rlpInt(v *big.Int) []byte { return rlpBytes(v.Bytes()) }

func rlpList(items ...[]byte) []byte {
	var body []byte
	for _, i := range items {
		body = append(body, i...)
	}
	return append(rlpLen(len(body), 0xc0), body...)
}

// Tx is an EIP-1559 (type 2) transaction.
type Tx struct {
	ChainID, Nonce, TipCap, FeeCap, Gas uint64
	To                                  Address
	Value                               *big.Int
	Data                                []byte
}

func (t Tx) fields() [][]byte {
	v := t.Value
	if v == nil {
		v = new(big.Int)
	}
	return [][]byte{rlpInt(new(big.Int).SetUint64(t.ChainID)), rlpInt(new(big.Int).SetUint64(t.Nonce)), rlpInt(new(big.Int).SetUint64(t.TipCap)),
		rlpInt(new(big.Int).SetUint64(t.FeeCap)), rlpInt(new(big.Int).SetUint64(t.Gas)), rlpBytes(t.To[:]), rlpInt(v), rlpBytes(t.Data), rlpList()}
}

// Sign returns the raw signed transaction.
func (t Tx) Sign(priv []byte) ([]byte, error) {
	sig, err := SignEth(priv, Keccak(append([]byte{2}, rlpList(t.fields()...)...)))
	if err != nil {
		return nil, err
	}
	f := append(t.fields(), rlpInt(new(big.Int).SetUint64(uint64(sig[64]-27))), rlpInt(new(big.Int).SetBytes(sig[:32])), rlpInt(new(big.Int).SetBytes(sig[32:64])))
	return append([]byte{2}, rlpList(f...)...), nil
}

func hexU(res json.RawMessage) (uint64, error) {
	var s string
	json.Unmarshal(res, &s)
	v, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok {
		return 0, errors.New("bad quantity")
	}
	return v.Uint64(), nil
}

// Send signs and broadcasts a call to `to`, estimating gas and fees, and waits for the receipt.
// Used by the on-chain verification tests; payments never need gas (facilitators sponsor it).
func (r *RPC) Send(ctx context.Context, priv []byte, chainID uint64, to Address, data []byte) (string, error) {
	from, err := AddressOf(priv)
	if err != nil {
		return "", err
	}
	call := map[string]string{"from": from.Hex(), "to": to.Hex(), "data": "0x" + hex.EncodeToString(data)}
	gasRes, err := r.Call(ctx, "eth_estimateGas", call)
	if err != nil {
		return "", err
	}
	gas, err := hexU(gasRes)
	if err != nil {
		return "", err
	}
	nres, err := r.Call(ctx, "eth_getTransactionCount", from.Hex(), "pending")
	if err != nil {
		return "", err
	}
	nonce, _ := hexU(nres)
	pres, err := r.Call(ctx, "eth_gasPrice")
	if err != nil {
		return "", err
	}
	price, _ := hexU(pres)
	tx := Tx{ChainID: chainID, Nonce: nonce, TipCap: price / 10, FeeCap: price*2 + 1000, Gas: gas * 13 / 10, To: to, Data: data}
	raw, err := tx.Sign(priv)
	if err != nil {
		return "", err
	}
	hres, err := r.Call(ctx, "eth_sendRawTransaction", "0x"+hex.EncodeToString(raw))
	if err != nil {
		return "", err
	}
	var hash string
	json.Unmarshal(hres, &hash)
	for i := 0; i < 40; i++ {
		time.Sleep(2 * time.Second)
		rec, err := r.Call(ctx, "eth_getTransactionReceipt", hash)
		if err != nil || string(rec) == "null" {
			continue
		}
		var rc struct{ Status string }
		json.Unmarshal(rec, &rc)
		if rc.Status != "0x1" {
			return hash, errors.New("transaction reverted: " + hash)
		}
		return hash, nil
	}
	return hash, errors.New("no receipt for " + hash)
}
