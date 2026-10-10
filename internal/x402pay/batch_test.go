package x402pay

import (
	"math/big"
	"testing"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
)

func testKeys(t *testing.T) Keys {
	k := evm.Keccak([]byte("test key"))
	a, err := evm.AddressOf(k)
	if err != nil {
		t.Fatal(err)
	}
	return Keys{EVM: k, EVMAdr: a}
}

func testOffer() Offer {
	reg := chain.Builtin()
	n, _ := reg.Find("eip155:8453")
	return Offer{Scheme: "batch-settlement", Network: n.CAIP, Net: n, Amount: big.NewInt(1000), Asset: n.USDC,
		PayTo: "0x1111111111111111111111111111111111111111", Timeout: 3600,
		Extra: map[string]any{"receiverAuthorizer": "0x2222222222222222222222222222222222222222", "withdrawDelay": float64(900), "name": "USDC", "version": "2"}}
}

func TestChannelIDIsStableAndChainBound(t *testing.T) {
	k := testKeys(t)
	cfg, err := BuildConfig(k, testOffer())
	if err != nil {
		t.Fatal(err)
	}
	a, b := cfg.ChannelID(8453), cfg.ChannelID(137)
	if a == b || a != cfg.ChannelID(8453) {
		t.Fatal("channel id")
	}
	cfg.Salt[0] = 1
	if cfg.ChannelID(8453) == a {
		t.Fatal("salt not bound")
	}
}

func TestVoucherRecoversToPayerAuthorizer(t *testing.T) {
	k := testKeys(t)
	o := testOffer()
	cfg, _ := BuildConfig(k, o)
	p, err := VoucherPayload(k, o, cfg, big.NewInt(1000))
	if err != nil {
		t.Fatal(err)
	}
	v := p["voucher"].(map[string]any)
	sig := mustHex(v["signature"].(string))
	id := cfg.ChannelID(8453)
	who, err := evm.RecoverEth(VoucherDigest(8453, id, big.NewInt(1000)), sig)
	if err != nil || who != k.EVMAdr {
		t.Fatal(who, err)
	}
}

func TestDepositPayloadShape(t *testing.T) {
	k := testKeys(t)
	o := testOffer()
	cfg, _ := BuildConfig(k, o)
	p, err := DepositPayload(k, o, cfg, big.NewInt(5000), big.NewInt(1000), time.Unix(1_800_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	d := p["deposit"].(map[string]any)
	auth := d["authorization"].(map[string]any)["erc3009Authorization"].(map[string]any)
	if p["type"] != "deposit" || d["amount"] != "5000" || auth["validAfter"] != "0" || len(auth["salt"].(string)) != 66 {
		t.Fatalf("%v", p)
	}
}

func TestDepositTarget(t *testing.T) {
	o := testOffer()
	if DepositTarget(o, big.NewInt(1000)).String() != "5000" {
		t.Fatal("multiplier")
	}
	o.Extra["minDeposit"] = "20000"
	if DepositTarget(o, big.NewInt(1000)).String() != "20000" {
		t.Fatal("hint")
	}
	o.Extra["minDeposit"] = "10" // below the request amount: ignored
	if DepositTarget(o, big.NewInt(1000)).String() != "5000" {
		t.Fatal("bad hint")
	}
	if DepositTarget(o, big.NewInt(9000)).String() != "9000" {
		t.Fatal("needed")
	}
}

func TestBuildConfigRejectsMissingAuthorizer(t *testing.T) {
	o := testOffer()
	delete(o.Extra, "receiverAuthorizer")
	if _, err := BuildConfig(testKeys(t), o); err == nil {
		t.Fatal("accepted")
	}
	o = testOffer()
	o.Extra["withdrawDelay"] = float64(5)
	if _, err := BuildConfig(testKeys(t), o); err == nil {
		t.Fatal("delay out of range accepted")
	}
}

func TestSessionStore(t *testing.T) {
	st := Store{Path: t.TempDir() + "/c.json"}
	id := "0x" + string(make([]byte, 0)) + "ab"
	if err := st.Put(Session{ChannelID: id, Charged: "5", Balance: "9"}); err != nil {
		t.Fatal(err)
	}
	g, _ := st.Get(id)
	if g == nil || g.Charged != "5" {
		t.Fatal("get")
	}
	st.Delete(id)
	if g, _ := st.Get(id); g != nil {
		t.Fatal("delete")
	}
}

func mustHex(s string) []byte {
	b := make([]byte, (len(s)-2)/2)
	for i := range b {
		var v byte
		for _, c := range s[2+2*i : 4+2*i] {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= byte(c - '0')
			default:
				v |= byte(c-'a') + 10
			}
		}
		b[i] = v
	}
	return b
}

// Oracle values come from go-ethereum's EIP-712 implementation (signer/core/apitypes), run offline
// on the same inputs.
func TestEIP712AgainstGoEthereum(t *testing.T) {
	a := func(n byte) evm.Address { var x evm.Address; x[19] = n; return x }
	cfg := ChannelConfig{Payer: a(1), PayerAuthorizer: a(2), Receiver: a(3), ReceiverAuthorizer: a(4), Token: a(5), WithdrawDelay: 900}
	cfg.Salt[31] = 1
	id := cfg.ChannelID(8453)
	if hexID(id) != "0x0126d6ab07381fa6a2cf52c81d417c447d30d497ea50e11af49d4b9178dc0b37" {
		t.Fatal("channel id", hexID(id))
	}
	if h := hexs(VoucherDigest(8453, id, big.NewInt(123456))); h != "31bfc6dfed07fc727ec2a1eef0e5f8db59468fc468ecc9767e1b408b9acafd33" {
		t.Fatal("voucher", h)
	}
	asset, _ := evm.ParseAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	coll, _ := evm.ParseAddress(ERC3009Collect)
	var n [32]byte
	n[0] = 0xaa
	d := ReceiveDigest(evm.Domain{Name: "USD Coin", Version: "2", ChainID: big.NewInt(8453), Contract: asset}, a(1), coll, big.NewInt(5000), big.NewInt(0), big.NewInt(1900000000), n)
	if h := hexs(d); h != "ff076a5f76b84b03278b75f913575cecbe88a649fbdd0883b0c18f7d27225358" {
		t.Fatal("receive", h)
	}
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, 0, len(b)*2)
	for _, c := range b {
		o = append(o, h[c>>4], h[c&15])
	}
	return string(o)
}
