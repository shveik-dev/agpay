// Package sol holds the Solana primitives the wallet needs: base58, keys (stdlib ed25519),
// the associated token address, v0 transaction building for the x402 exact scheme and a small
// JSON-RPC client.
package sol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"
)

const b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func B58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	var out []byte
	base, mod := big.NewInt(58), new(big.Int)
	for n.Sign() > 0 {
		n.DivMod(n, base, mod)
		out = append(out, b58[mod.Int64()])
	}
	for _, c := range b {
		if c != 0 {
			break
		}
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func B58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	base := big.NewInt(58)
	for _, c := range []byte(s) {
		i := bytes.IndexByte([]byte(b58), c)
		if i < 0 {
			return nil, errors.New("invalid base58 character")
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	z := 0
	for z < len(s) && s[z] == '1' {
		z++
	}
	return append(make([]byte, z), out...), nil
}

type Address [32]byte

func (a Address) String() string { return B58Encode(a[:]) }

func ParseAddress(s string) (Address, error) {
	var a Address
	b, err := B58Decode(s)
	if err != nil || len(b) != 32 {
		return a, fmt.Errorf("not a Solana address: %q", s)
	}
	copy(a[:], b)
	return a, nil
}

func mustAddr(s string) Address {
	a, err := ParseAddress(s)
	if err != nil {
		panic(err)
	}
	return a
}

var (
	SystemProgram          = Address{}
	TokenProgram           = mustAddr("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	Token2022Program       = mustAddr("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	AssociatedTokenProgram = mustAddr("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	ComputeBudgetProgram   = mustAddr("ComputeBudget111111111111111111111111111111")
	MemoProgram            = mustAddr("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
)

// KeyFromSeed returns the ed25519 key of a 32-byte seed (the same key every Solana wallet derives).
func KeyFromSeed(seed []byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(seed) }

func AddressOf(k ed25519.PrivateKey) Address {
	var a Address
	copy(a[:], k.Public().(ed25519.PublicKey))
	return a
}

// ---- on-curve check (program derived addresses must be off the curve) ----

var (
	fp = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	fd = func() *big.Int { // d = -121665/121666
		n := new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), fp))
		return n.Mod(n, fp)
	}()
	fexp = new(big.Int).Rsh(new(big.Int).Sub(fp, big.NewInt(1)), 1)
)

// onCurve reports whether 32 bytes decode to a point on edwards25519.
func onCurve(b []byte) bool {
	yb := make([]byte, 32)
	copy(yb, b)
	yb[31] &= 0x7f
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		yb[i], yb[j] = yb[j], yb[i]
	}
	y := new(big.Int).SetBytes(yb)
	if y.Cmp(fp) >= 0 {
		return false
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, fp)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, fp)
	v := new(big.Int).Mul(fd, y2)
	v.Add(v, big.NewInt(1))
	v.Mod(v, fp)
	r := new(big.Int).Mul(u, new(big.Int).ModInverse(v, fp))
	r.Mod(r, fp)
	if r.Sign() == 0 {
		return b[31]&0x80 == 0
	}
	return new(big.Int).Exp(r, fexp, fp).Cmp(big.NewInt(1)) == 0
}

func findPDA(seeds [][]byte, program Address) (Address, error) {
	for bump := 255; bump >= 0; bump-- {
		h := sha256.New()
		for _, s := range seeds {
			h.Write(s)
		}
		h.Write([]byte{byte(bump)})
		h.Write(program[:])
		h.Write([]byte("ProgramDerivedAddress"))
		sum := h.Sum(nil)
		if !onCurve(sum) {
			var a Address
			copy(a[:], sum)
			return a, nil
		}
	}
	return Address{}, errors.New("no program address")
}

// ATA derives the associated token account of (owner, mint) under a token program.
func ATA(owner, mint, tokenProgram Address) (Address, error) {
	return findPDA([][]byte{owner[:], tokenProgram[:], mint[:]}, AssociatedTokenProgram)
}

// ---- transactions ----

type Meta struct {
	Key              Address
	Signer, Writable bool
}

type Instruction struct {
	Program  Address
	Accounts []Meta
	Data     []byte
}

func SetComputeUnitLimit(units uint32) Instruction {
	d := make([]byte, 5)
	d[0] = 2
	binary.LittleEndian.PutUint32(d[1:], units)
	return Instruction{Program: ComputeBudgetProgram, Data: d}
}

func SetComputeUnitPrice(microLamports uint64) Instruction {
	d := make([]byte, 9)
	d[0] = 3
	binary.LittleEndian.PutUint64(d[1:], microLamports)
	return Instruction{Program: ComputeBudgetProgram, Data: d}
}

func TransferChecked(tokenProgram, source, mint, dest, authority Address, amount uint64, decimals uint8) Instruction {
	d := make([]byte, 10)
	d[0] = 12
	binary.LittleEndian.PutUint64(d[1:9], amount)
	d[9] = decimals
	return Instruction{Program: tokenProgram, Accounts: []Meta{{source, false, true}, {mint, false, false}, {dest, false, true}, {authority, true, false}}, Data: d}
}

func Memo(data []byte) Instruction { return Instruction{Program: MemoProgram, Data: data} }

func compact(n int) []byte {
	var out []byte
	for {
		b := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

// Message compiles a v0 message (no lookup tables) the way wallets do: fee payer first, then
// writable signers, readonly signers, writable non-signers, readonly non-signers.
func Message(feePayer Address, ixs []Instruction, blockhash [32]byte) []byte {
	type flags struct{ signer, writable bool }
	order := []Address{feePayer}
	fl := map[Address]*flags{feePayer: {true, true}}
	touch := func(k Address, s, w bool) {
		f, ok := fl[k]
		if !ok {
			f = &flags{}
			fl[k] = f
			order = append(order, k)
		}
		f.signer = f.signer || s
		f.writable = f.writable || w
	}
	for _, ix := range ixs {
		touch(ix.Program, false, false)
		for _, m := range ix.Accounts {
			touch(m.Key, m.Signer, m.Writable)
		}
	}
	var ws, rs, wn, rn []Address
	for _, k := range order[1:] {
		f := fl[k]
		switch {
		case f.signer && f.writable:
			ws = append(ws, k)
		case f.signer:
			rs = append(rs, k)
		case f.writable:
			wn = append(wn, k)
		default:
			rn = append(rn, k)
		}
	}
	keys := append(append(append(append([]Address{feePayer}, ws...), rs...), wn...), rn...)
	idx := map[Address]byte{}
	for i, k := range keys {
		idx[k] = byte(i)
	}
	out := []byte{0x80, byte(1 + len(ws) + len(rs)), byte(len(rs)), byte(len(rn))}
	out = append(out, compact(len(keys))...)
	for _, k := range keys {
		out = append(out, k[:]...)
	}
	out = append(out, blockhash[:]...)
	out = append(out, compact(len(ixs))...)
	for _, ix := range ixs {
		out = append(out, idx[ix.Program])
		out = append(out, compact(len(ix.Accounts))...)
		for _, m := range ix.Accounts {
			out = append(out, idx[m.Key])
		}
		out = append(out, compact(len(ix.Data))...)
		out = append(out, ix.Data...)
	}
	return append(out, 0) // no address table lookups
}

// SignedPartial serialises a transaction whose signature slots exist for every required signer but
// only ours is filled; the fee payer (slot 0) signs later, at settlement.
func SignedPartial(msg []byte, keys []Address, signer ed25519.PrivateKey) ([]byte, error) {
	need := int(msg[1])
	me := AddressOf(signer)
	slot := -1
	for i := 0; i < need && i < len(keys); i++ {
		if keys[i] == me {
			slot = i
		}
	}
	if slot < 0 {
		return nil, errors.New("our key is not a required signer of this transaction")
	}
	out := compact(need)
	for i := 0; i < need; i++ {
		if i == slot {
			out = append(out, ed25519.Sign(signer, msg)...)
		} else {
			out = append(out, make([]byte, 64)...)
		}
	}
	return append(out, msg...), nil
}

// AccountKeys lists the static account keys of a message built by Message.
func AccountKeys(msg []byte) []Address {
	pos := 4
	n, used := 0, 0
	for shift := 0; ; shift += 7 {
		b := msg[pos+used]
		n |= int(b&0x7f) << shift
		used++
		if b&0x80 == 0 {
			break
		}
	}
	pos += used
	keys := make([]Address, n)
	for i := range keys {
		copy(keys[i][:], msg[pos+32*i:])
	}
	return keys
}

// ---- RPC ----

type RPC struct {
	URLs []string
	HTTP *http.Client
}

func (r *RPC) Call(ctx context.Context, method string, params ...any) (json.RawMessage, error) {
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
			Result json.RawMessage           `json:"result"`
			Error  *struct{ Message string } `json:"error"`
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

func (r *RPC) Blockhash(ctx context.Context) ([32]byte, error) {
	var bh [32]byte
	res, err := r.Call(ctx, "getLatestBlockhash", map[string]string{"commitment": "confirmed"})
	if err != nil {
		return bh, err
	}
	var v struct{ Value struct{ Blockhash string } }
	if err := json.Unmarshal(res, &v); err != nil {
		return bh, err
	}
	b, err := B58Decode(v.Value.Blockhash)
	if err != nil || len(b) != 32 {
		return bh, errors.New("bad blockhash")
	}
	copy(bh[:], b)
	return bh, nil
}

// AccountInfo returns the owner program and whether the account exists.
func (r *RPC) AccountOwner(ctx context.Context, a Address) (owner Address, exists bool, err error) {
	res, err := r.Call(ctx, "getAccountInfo", a.String(), map[string]string{"encoding": "base64"})
	if err != nil {
		return owner, false, err
	}
	var v struct {
		Value *struct {
			Owner string
			Data  []string
		}
	}
	if err := json.Unmarshal(res, &v); err != nil {
		return owner, false, err
	}
	if v.Value == nil {
		return owner, false, nil
	}
	o, err := ParseAddress(v.Value.Owner)
	return o, true, err
}

func (r *RPC) TokenBalance(ctx context.Context, account Address) (*big.Int, error) {
	res, err := r.Call(ctx, "getTokenAccountBalance", account.String())
	if err != nil {
		return big.NewInt(0), nil // a missing account holds nothing
	}
	var v struct{ Value struct{ Amount string } }
	if err := json.Unmarshal(res, &v); err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(v.Value.Amount, 10)
	if !ok {
		return nil, errors.New("bad balance")
	}
	return n, nil
}

func (r *RPC) Lamports(ctx context.Context, a Address) (uint64, error) {
	res, err := r.Call(ctx, "getBalance", a.String())
	if err != nil {
		return 0, err
	}
	var v struct{ Value uint64 }
	return v.Value, json.Unmarshal(res, &v)
}

func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
