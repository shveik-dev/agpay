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
	return r.send(ctx, priv, chainID, to, nil, data, 0)
}

// SendValue sends an exact native amount (plain transfer, 21000 gas).
func (r *RPC) SendValue(ctx context.Context, priv []byte, chainID uint64, to Address, value *big.Int) (string, error) {
	return r.send(ctx, priv, chainID, to, value, nil, 21000)
}

// SendAll moves the whole native balance (minus the exact fee of a plain transfer) to an address.
func (r *RPC) SendAll(ctx context.Context, priv []byte, chainID uint64, to Address) (string, *big.Int, error) {
	from, err := AddressOf(priv)
	if err != nil {
		return "", nil, err
	}
	bal, err := r.NativeBalance(ctx, from)
	if err != nil {
		return "", nil, err
	}
	pres, err := r.Call(ctx, "eth_gasPrice")
	if err != nil {
		return "", nil, err
	}
	price, _ := hexU(pres)
	feeCap := price*2 + 1000
	reserve := new(big.Int).Mul(big.NewInt(21000), new(big.Int).SetUint64(feeCap))
	reserve.Add(reserve, big.NewInt(3_000_000_000)) // rollups (Base, OP) also charge an L1 data fee that the balance check includes
	value := new(big.Int).Sub(bal, reserve)
	if value.Sign() <= 0 {
		return "", nil, errors.New("the native balance does not cover the network fee")
	}
	tx, err := r.sendAt(ctx, priv, chainID, to, value, nil, 21000, price)
	return tx, value, err
}

func (r *RPC) send(ctx context.Context, priv []byte, chainID uint64, to Address, value *big.Int, data []byte, fixedGas uint64) (string, error) {
	return r.sendAt(ctx, priv, chainID, to, value, data, fixedGas, 0)
}

func (r *RPC) sendAt(ctx context.Context, priv []byte, chainID uint64, to Address, value *big.Int, data []byte, fixedGas, fixedPrice uint64) (string, error) {
	from, err := AddressOf(priv)
	if err != nil {
		return "", err
	}
	gas := fixedGas
	if gas == 0 {
		call := map[string]string{"from": from.Hex(), "to": to.Hex(), "data": "0x" + hex.EncodeToString(data)}
		gasRes, err := r.Call(ctx, "eth_estimateGas", call)
		if err != nil {
			return "", err
		}
		if gas, err = hexU(gasRes); err != nil {
			return "", err
		}
		gas = gas * 13 / 10
	}
	nres, err := r.Call(ctx, "eth_getTransactionCount", from.Hex(), "pending")
	if err != nil {
		return "", err
	}
	nonce, _ := hexU(nres)
	price := fixedPrice
	if price == 0 {
		pres, err := r.Call(ctx, "eth_gasPrice")
		if err != nil {
			return "", err
		}
		price, _ = hexU(pres)
	}
	tx := Tx{ChainID: chainID, Nonce: nonce, TipCap: price / 10, FeeCap: price*2 + 1000, Gas: gas, To: to, Value: value, Data: data}
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
