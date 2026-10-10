package evm

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"testing"
)

func TestChecksumVectors(t *testing.T) {
	for _, s := range []string{"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359", "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB", "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"} {
		a, err := ParseAddress(s)
		if err != nil || a.Hex() != s {
			t.Fatalf("%s -> %s %v", s, a.Hex(), err)
		}
	}
}

func TestSignRecover(t *testing.T) {
	k := Keccak([]byte("k"))
	addr, _ := AddressOf(k)
	d := PersonalHash([]byte("hello"))
	sig, _ := SignEth(k, d)
	if sig[64] != 27 && sig[64] != 28 {
		t.Fatal("v")
	}
	got, err := RecoverEth(d, sig)
	if err != nil || got != addr {
		t.Fatal(got, err)
	}
}

func TestEIP712Mail(t *testing.T) {
	// the EIP-712 spec example domain separator (Ether Mail) pins the domain encoding.
	c, _ := ParseAddress("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC")
	d := Domain{Name: "Ether Mail", Version: "1", ChainID: big.NewInt(1), Contract: c}
	want := "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
	if got := hexs(d.Separator()); got != want {
		t.Fatal(got)
	}
	_ = bytes.Equal
}

func hexs(b []byte) string {
	const h = "0123456789abcdef"
	o := make([]byte, 0, len(b)*2)
	for _, c := range b {
		o = append(o, h[c>>4], h[c&15])
	}
	return string(o)
}

func TestEIP3009DigestGolden(t *testing.T) {
	b, _ := os.ReadFile("../../testdata/golden.json")
	var g struct {
		Auth3009 string `json:"auth3009"`
	}
	json.Unmarshal(b, &g)
	from, _ := ParseAddress("0x1dc6E6A529D9e2626d26167C55290f353d278e34")
	to, _ := ParseAddress("0xbBa594F5549392DF7A8182049291b605948F5F86")
	asset, _ := ParseAddress("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
	var nonce [32]byte
	nonce[0], nonce[31] = 0xab, 0xcd
	d := AuthDigest(Domain{Name: "USD Coin", Version: "2", ChainID: big.NewInt(8453), Contract: asset},
		Auth{From: from, To: to, Value: big.NewInt(31665), ValidAfter: big.NewInt(1000), Until: big.NewInt(2000), Nonce: nonce})
	if hexs(d) != g.Auth3009 {
		t.Fatalf("got %s want %s", hexs(d), g.Auth3009)
	}
}
