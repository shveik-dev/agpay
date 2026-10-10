package sol

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type golden struct {
	ATAs []struct{ Owner, ATA string } `json:"atas"`
	Msg  string                        `json:"msg"`
}

func TestGoldenAgainstServerImplementation(t *testing.T) {
	var g golden
	b, err := os.ReadFile("../../testdata/golden.json")
	if err != nil {
		t.Fatal(err)
	}
	json.Unmarshal(b, &g)
	mint := mustAddr("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
	for _, v := range g.ATAs {
		got, err := ATA(mustAddr(v.Owner), mint, TokenProgram)
		if err != nil || got.String() != v.ATA {
			t.Fatalf("ata %s: got %s want %s (%v)", v.Owner, got, v.ATA, err)
		}
	}
	var fp, src, dst, auth Address
	fp[0], src[0], dst[0], auth[0] = 1, 2, 3, 4
	var bh [32]byte
	bh[5] = 9
	msg := Message(fp, []Instruction{SetComputeUnitLimit(50000), SetComputeUnitPrice(1),
		TransferChecked(TokenProgram, src, mint, dst, auth, 31665, 6), Memo([]byte("0123456789abcdef"))}, bh)
	if hex.EncodeToString(msg) != g.Msg {
		t.Fatalf("message differs\n got %x\nwant %s", msg, g.Msg)
	}
}

func TestBase58RoundTrip(t *testing.T) {
	for _, s := range []string{"11111111111111111111111111111111", "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"} {
		b, err := B58Decode(s)
		if err != nil || B58Encode(b) != s {
			t.Fatal(s)
		}
	}
}
