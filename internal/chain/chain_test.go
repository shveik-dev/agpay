package chain

import (
	"math/big"
	"testing"
)

func TestParseAndFormat(t *testing.T) {
	n := Builtin()
	b, _ := n.Find("base")
	for in, want := range map[string]string{"1": "1000000", "$0.013": "13000", "0.000001": "1", "10.5": "10500000"} {
		v, err := ParseUSD(in)
		if err != nil || v.String() != want {
			t.Fatal(in, v, err)
		}
	}
	for _, bad := range []string{"", "-1", "1.0000001", "abc", "1e3"} {
		if _, err := ParseUSD(bad); err == nil {
			t.Fatal("accepted", bad)
		}
	}
	if b.Format(big.NewInt(31665)) != "0.031665" || b.Format(big.NewInt(2000000)) != "2" {
		t.Fatal("format")
	}
	if !b.IsAsset("0x833589fcd6edb6e08f4c7c32d4f71b54bda02913") {
		t.Fatal("asset case")
	}
}
