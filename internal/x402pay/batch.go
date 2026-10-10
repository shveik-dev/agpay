package x402pay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/shveik-dev/agpay/internal/evm"
)

// The batch-settlement scheme on EVM (x402 specs/schemes/batch-settlement). Constants are the
// canonical deployments of x402BatchSettlement and its ERC-3009 deposit collector.
const (
	BatchContract  = "0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003"
	ERC3009Collect = "0x4020806089470a89826cB9fB1f4059150b550004"
	minWithdrawDel = 900
	maxWithdrawDel = 2_592_000
	// DepositMultiplier sizes a new channel when the server announces no extra.minDeposit.
	DepositMultiplier = 5
)

var (
	typeChannelConfig = evm.Keccak([]byte("ChannelConfig(address payer,address payerAuthorizer,address receiver,address receiverAuthorizer,address token,uint40 withdrawDelay,bytes32 salt)"))
	typeVoucher       = evm.Keccak([]byte("Voucher(bytes32 channelId,uint128 maxClaimableAmount)"))
	typeReceiveAuth   = evm.Keccak([]byte("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"))
)

type ChannelConfig struct {
	Payer, PayerAuthorizer, Receiver, ReceiverAuthorizer, Token evm.Address
	WithdrawDelay                                               int64
	Salt                                                        [32]byte
}

func pad(b []byte) []byte { o := make([]byte, 32); copy(o[32-len(b):], b); return o }

func batchDomain(chainID int64) evm.Domain {
	c, _ := evm.ParseAddress(BatchContract)
	return evm.Domain{Name: "x402 Batch Settlement", Version: "1", ChainID: big.NewInt(chainID), Contract: c}
}

// ChannelID is the EIP-712 hash of the config under the chain-bound batch-settlement domain.
func (c ChannelConfig) ChannelID(chainID int64) [32]byte {
	h := evm.Keccak(typeChannelConfig, pad(c.Payer[:]), pad(c.PayerAuthorizer[:]), pad(c.Receiver[:]), pad(c.ReceiverAuthorizer[:]), pad(c.Token[:]),
		pad(big.NewInt(c.WithdrawDelay).Bytes()), c.Salt[:])
	var id [32]byte
	copy(id[:], evm.TypedDigest(batchDomain(chainID), h))
	return id
}

func (c ChannelConfig) JSON() map[string]any {
	return map[string]any{"payer": c.Payer.Hex(), "payerAuthorizer": c.PayerAuthorizer.Hex(), "receiver": c.Receiver.Hex(),
		"receiverAuthorizer": c.ReceiverAuthorizer.Hex(), "token": c.Token.Hex(), "withdrawDelay": c.WithdrawDelay,
		"salt": "0x" + hex.EncodeToString(c.Salt[:])}
}

// VoucherDigest is what a voucher signature covers: Voucher(bytes32 channelId, uint128 max).
func VoucherDigest(chainID int64, id [32]byte, max *big.Int) []byte {
	return evm.TypedDigest(batchDomain(chainID), evm.Keccak(typeVoucher, id[:], pad(max.Bytes())))
}

func hexID(id [32]byte) string { return "0x" + hex.EncodeToString(id[:]) }

// BuildConfig maps an offer onto the channel: the server fixes receiver, receiverAuthorizer, token
// and delay; the wallet contributes payer, payerAuthorizer (itself) and a zero salt.
func BuildConfig(k Keys, o Offer) (ChannelConfig, error) {
	var c ChannelConfig
	var err error
	ra, _ := o.Extra["receiverAuthorizer"].(string)
	if c.ReceiverAuthorizer, err = evm.ParseAddress(ra); err != nil || c.ReceiverAuthorizer == (evm.Address{}) {
		return c, errors.New("the offer must carry a non-zero extra.receiverAuthorizer")
	}
	if c.Receiver, err = evm.ParseAddress(o.PayTo); err != nil {
		return c, err
	}
	if c.Token, err = evm.ParseAddress(o.Asset); err != nil {
		return c, err
	}
	c.WithdrawDelay = 900
	if v, ok := o.Extra["withdrawDelay"].(float64); ok {
		c.WithdrawDelay = int64(v)
	}
	if c.WithdrawDelay < minWithdrawDel || c.WithdrawDelay > maxWithdrawDel {
		return c, fmt.Errorf("withdrawDelay %d is outside 15 minutes .. 30 days", c.WithdrawDelay)
	}
	c.Payer, c.PayerAuthorizer = k.EVMAdr, k.EVMAdr
	return c, nil
}

// ---- local channel sessions ----

type Session struct {
	ChannelID string `json:"channel_id"`
	Network   string `json:"network"`
	Host      string `json:"host,omitempty"`
	Receiver  string `json:"receiver"`
	Charged   string `json:"charged_cumulative"` // what the server has charged so far, as the wallet counts it
	Balance   string `json:"balance"`            // deposited minus refunded
	Signed    string `json:"signed_max,omitempty"`
	Signature string `json:"signature,omitempty"`
	UpdatedAt int64  `json:"updated_at"`
}

type Store struct{ Path string }

func (s Store) with(fn func(m map[string]Session) error) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	lk, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer lk.Close()
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	m := map[string]Session{}
	if b, err := os.ReadFile(s.Path); err == nil {
		json.Unmarshal(b, &m)
	}
	before, _ := json.Marshal(m)
	if err := fn(m); err != nil {
		return err
	}
	after, _ := json.MarshalIndent(m, "", "  ")
	if string(before) == string(mustCompact(after)) {
		return nil
	}
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, append(after, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

func mustCompact(b []byte) []byte {
	var v map[string]Session
	json.Unmarshal(b, &v)
	o, _ := json.Marshal(v)
	return o
}

func (s Store) Get(id string) (*Session, error) {
	var out *Session
	err := s.with(func(m map[string]Session) error {
		if v, ok := m[strings.ToLower(id)]; ok {
			c := v
			out = &c
		}
		return nil
	})
	return out, err
}

func (s Store) Put(v Session) error {
	v.UpdatedAt = time.Now().Unix()
	return s.with(func(m map[string]Session) error { m[strings.ToLower(v.ChannelID)] = v; return nil })
}

func (s Store) Delete(id string) error {
	return s.with(func(m map[string]Session) error { delete(m, strings.ToLower(id)); return nil })
}

func (s Store) All() ([]Session, error) {
	var out []Session
	err := s.with(func(m map[string]Session) error {
		for _, v := range m {
			out = append(out, v)
		}
		return nil
	})
	return out, err
}

// OnchainChannel reads channels(channelId) -> (balance, totalClaimed).
func OnchainChannel(ctx context.Context, rpc *evm.RPC, id [32]byte) (balance, claimed *big.Int, err error) {
	data := append(evm.Keccak([]byte("channels(bytes32)"))[:4], id[:]...)
	res, err := rpc.Call(ctx, "eth_call", map[string]string{"to": BatchContract, "data": "0x" + hex.EncodeToString(data)}, "latest")
	if err != nil {
		return nil, nil, err
	}
	var s string
	json.Unmarshal(res, &s)
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) < 64 {
		return nil, nil, errors.New("channels() returned no data")
	}
	return new(big.Int).SetBytes(b[:32]), new(big.Int).SetBytes(b[32:64]), nil
}

// ---- payload builders ----

func (k Keys) signVoucher(chainID int64, id [32]byte, max *big.Int) (map[string]any, error) {
	sig, err := evm.SignEth(k.EVM, VoucherDigest(chainID, id, max))
	if err != nil {
		return nil, err
	}
	return map[string]any{"channelId": hexID(id), "maxClaimableAmount": max.String(), "signature": "0x" + hex.EncodeToString(sig)}, nil
}

// VoucherPayload is the cumulative-voucher payload for an open channel.
func VoucherPayload(k Keys, o Offer, cfg ChannelConfig, max *big.Int) (map[string]any, error) {
	id := cfg.ChannelID(o.Net.ChainID)
	v, err := k.signVoucher(o.Net.ChainID, id, max)
	if err != nil {
		return nil, err
	}
	return map[string]any{"type": "voucher", "channelConfig": cfg.JSON(), "voucher": v}, nil
}

// DepositPayload funds (or tops up) the channel with an ERC-3009 receiveWithAuthorization to the
// canonical deposit collector, plus the first voucher. The authorization nonce is
// keccak(abi.encode(channelId, salt)) so the collector can bind the deposit to this channel.
func DepositPayload(k Keys, o Offer, cfg ChannelConfig, deposit, max *big.Int, now time.Time) (map[string]any, error) {
	id := cfg.ChannelID(o.Net.ChainID)
	dom, err := tokenDomain(o)
	if err != nil {
		return nil, err
	}
	salt := randBytes(32)
	nonce := evm.Keccak(id[:], salt)
	coll, _ := evm.ParseAddress(ERC3009Collect)
	t := o.Timeout
	if t <= 0 || t > 900 {
		t = 900 // a deposit authorization is redeemed within seconds; never leave it open for long
	}
	until := now.Unix() + t
	var n32 [32]byte
	copy(n32[:], nonce)
	digest := ReceiveDigest(dom, k.EVMAdr, coll, deposit, big.NewInt(0), big.NewInt(until), n32)
	sig, err := evm.SignEth(k.EVM, digest)
	if err != nil {
		return nil, err
	}
	v, err := k.signVoucher(o.Net.ChainID, id, max)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"type": "deposit", "channelConfig": cfg.JSON(), "voucher": v,
		"deposit": map[string]any{"amount": deposit.String(), "authorization": map[string]any{"erc3009Authorization": map[string]any{
			"validAfter": "0", "validBefore": fmt.Sprint(until), "salt": "0x" + hex.EncodeToString(salt), "signature": "0x" + hex.EncodeToString(sig)}}},
	}, nil
}

// ReceiveDigest is the EIP-712 digest of ERC-3009 receiveWithAuthorization.
func ReceiveDigest(dom evm.Domain, from, to evm.Address, value, after, before *big.Int, nonce [32]byte) []byte {
	return evm.TypedDigest(dom, evm.Keccak(typeReceiveAuth, pad(from[:]), pad(to[:]), pad(value.Bytes()), pad(after.Bytes()), pad(before.Bytes()), nonce[:]))
}

// RefundPayload asks the server for a cooperative refund: a zero-charge voucher (ceiling equal to
// the cumulative charged amount) and an optional partial amount.
func RefundPayload(k Keys, o Offer, cfg ChannelConfig, charged, amount *big.Int) (map[string]any, error) {
	id := cfg.ChannelID(o.Net.ChainID)
	v, err := k.signVoucher(o.Net.ChainID, id, charged)
	if err != nil {
		return nil, err
	}
	p := map[string]any{"type": "refund", "channelConfig": cfg.JSON(), "voucher": v}
	if amount != nil {
		p["amount"] = amount.String()
	}
	return p, nil
}

// DepositTarget picks the deposit: the server's announced minDeposit when valid (a positive integer
// not below the request amount), else DepositMultiplier x the request, never below what the next
// voucher needs.
func DepositTarget(o Offer, needed *big.Int, multiplier int) *big.Int {
	if multiplier < 3 {
		multiplier = DepositMultiplier // the spec allows no less than 3; 5 is the default
	}
	target := new(big.Int).Mul(big.NewInt(int64(multiplier)), o.Amount)
	if s, ok := o.Extra["minDeposit"].(string); ok {
		if v, ok := new(big.Int).SetString(s, 10); ok && v.Sign() > 0 && v.Cmp(o.Amount) >= 0 && !strings.HasPrefix(s, "+") {
			target = v
		}
	}
	if needed.Cmp(target) > 0 {
		return new(big.Int).Set(needed)
	}
	return target
}

// Resync handles a corrective 402: the server returns its channelState and the last voucher it
// holds. The wallet adopts the server's cumulative only when that voucher verifies against its own
// signer, is not below what the chain says is claimed, and is at least the server's charge.
func Resync(ctx context.Context, rpc *evm.RPC, k Keys, o Offer, cfg ChannelConfig, st Store) (bool, error) {
	cs, _ := o.Extra["channelState"].(map[string]any)
	vs, _ := o.Extra["voucherState"].(map[string]any)
	id := cfg.ChannelID(o.Net.ChainID)
	bal, claimed, err := OnchainChannel(ctx, rpc, id)
	if err != nil {
		return false, err
	}
	next := Session{ChannelID: hexID(id), Network: o.Net.CAIP, Receiver: cfg.Receiver.Hex(), Balance: bal.String(), Charged: claimed.String()}
	if old, _ := st.Get(hexID(id)); old != nil {
		next.Host = old.Host
	}
	if cs != nil && vs != nil {
		charged, ok1 := new(big.Int).SetString(fmt.Sprint(cs["chargedCumulativeAmount"]), 10)
		signed, ok2 := new(big.Int).SetString(fmt.Sprint(vs["signedMaxClaimable"]), 10)
		sigHex, _ := vs["signature"].(string)
		sig, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
		if ok1 && ok2 && err == nil && charged.Cmp(signed) <= 0 && charged.Cmp(claimed) >= 0 {
			if who, err := evm.RecoverEth(VoucherDigest(o.Net.ChainID, id, signed), sig); err == nil && who == cfg.PayerAuthorizer {
				next.Charged, next.Signed, next.Signature = charged.String(), signed.String(), sigHex
			}
		}
	}
	if err := st.Put(next); err != nil {
		return false, err
	}
	return true, nil
}

// DepositCalldata ABI-encodes x402BatchSettlement.deposit(config, amount, collector, collectorData)
// with the ERC-3009 collector data (validAfter, validBefore, salt, signature). A facilitator sends
// this transaction; the wallet only builds it for verification (eth_call) and tests.
func DepositCalldata(cfg ChannelConfig, amount *big.Int, validAfter, validBefore int64, salt, sig []byte) []byte {
	w := func(b []byte) []byte { return pad(b) }
	coll, _ := evm.ParseAddress(ERC3009Collect)
	// collectorData = abi.encode(uint256, uint256, uint256, bytes)
	cd := append(w(big.NewInt(validAfter).Bytes()), w(big.NewInt(validBefore).Bytes())...)
	cd = append(cd, w(new(big.Int).SetBytes(salt).Bytes())...)
	cd = append(cd, w(big.NewInt(128).Bytes())...)
	cd = append(cd, w(big.NewInt(int64(len(sig))).Bytes())...)
	cd = append(cd, rightPad(sig)...)
	out := evm.Keccak([]byte("deposit((address,address,address,address,address,uint40,bytes32),uint128,address,bytes)"))[:4]
	for _, a := range []evm.Address{cfg.Payer, cfg.PayerAuthorizer, cfg.Receiver, cfg.ReceiverAuthorizer, cfg.Token} {
		out = append(out, w(a[:])...)
	}
	out = append(out, w(big.NewInt(cfg.WithdrawDelay).Bytes())...)
	out = append(out, cfg.Salt[:]...)
	out = append(out, w(amount.Bytes())...)
	out = append(out, w(coll[:])...)
	out = append(out, w(big.NewInt(320).Bytes())...) // offset of collectorData: 10 head words
	out = append(out, w(big.NewInt(int64(len(cd))).Bytes())...)
	return append(out, rightPad(cd)...)
}

func rightPad(b []byte) []byte {
	out := append([]byte(nil), b...)
	for len(out)%32 != 0 {
		out = append(out, 0)
	}
	return out
}

func cfgWords(cfg ChannelConfig) []byte {
	var out []byte
	for _, a := range []evm.Address{cfg.Payer, cfg.PayerAuthorizer, cfg.Receiver, cfg.ReceiverAuthorizer, cfg.Token} {
		out = append(out, pad(a[:])...)
	}
	out = append(out, pad(big.NewInt(cfg.WithdrawDelay).Bytes())...)
	return append(out, cfg.Salt[:]...)
}

// ClaimCalldata encodes x402BatchSettlement.claim([{voucher:{channel,maxClaimableAmount}, signature,
// totalClaimed}]) for one voucher. The receiver (or receiverAuthorizer) calls it to redeem the latest voucher.
func ClaimCalldata(cfg ChannelConfig, max *big.Int, sig []byte, totalClaimed *big.Int) []byte {
	out := evm.Keccak([]byte("claim((((address,address,address,address,address,uint40,bytes32),uint128),bytes,uint128)[])"))[:4]
	out = append(out, pad(big.NewInt(32).Bytes())...) // offset of the array
	out = append(out, pad(big.NewInt(1).Bytes())...)  // length
	out = append(out, pad(big.NewInt(32).Bytes())...) // offset of element 0, from the start of the array body
	// element: voucher tuple (static: config 7 words + max), offset to the signature, totalClaimed
	el := append(cfgWords(cfg), pad(max.Bytes())...)
	el = append(el, pad(big.NewInt(320).Bytes())...)
	el = append(el, pad(totalClaimed.Bytes())...)
	el = append(el, pad(big.NewInt(int64(len(sig))).Bytes())...)
	el = append(el, rightPad(sig)...)
	return append(out, el...)
}

// RefundCalldata encodes refund(config, amount): the receiver returns unclaimed escrow to the payer.
func RefundCalldata(cfg ChannelConfig, amount *big.Int) []byte {
	out := evm.Keccak([]byte("refund((address,address,address,address,address,uint40,bytes32),uint128)"))[:4]
	out = append(out, cfgWords(cfg)...)
	return append(out, pad(amount.Bytes())...)
}
