package x402pay

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
)

// TestLiveChannelLifecycle runs a real channel on Base mainnet with the wallet acting as payer AND
// as the server's receiver/authorizer (no third-party server exists to test against): a real
// deposit transaction, a signed voucher that the contract itself verifies (simulated claim), a
// real claim, and a cooperative refund of the rest. Spends gas and ~1 cent of USDC (the claimed part
// returns to the same wallet via settle). Runs only with AGPAY_LIVE_KEY set.
func TestLiveChannelLifecycle(t *testing.T) {
	keyHex := os.Getenv("AGPAY_LIVE_KEY")
	if keyHex == "" {
		t.Skip("set AGPAY_LIVE_KEY to run against Base mainnet")
	}
	kb, _ := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
	addr, _ := evm.AddressOf(kb)
	k := Keys{EVM: kb, EVMAdr: addr}
	n, _ := chain.Builtin().Find("eip155:8453")
	o := Offer{Scheme: "batch-settlement", Network: n.CAIP, Net: n, Amount: big.NewInt(1000), Asset: n.USDC, PayTo: addr.Hex(), Timeout: 600,
		Extra: map[string]any{"receiverAuthorizer": addr.Hex(), "withdrawDelay": float64(900), "name": "USD Coin", "version": "2"}}
	cfg, err := BuildConfig(k, o)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Salt = [32]byte{}
	copy(cfg.Salt[:], evm.Keccak([]byte(time.Now().String()))) // a fresh channel each run
	id := cfg.ChannelID(8453)
	rpc := &evm.RPC{URLs: n.RPC}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	deposit := big.NewInt(3000)
	p, err := DepositPayload(k, o, cfg, deposit, big.NewInt(1000), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := p["deposit"].(map[string]any)["authorization"].(map[string]any)["erc3009Authorization"].(map[string]any)
	var until int64
	json.Unmarshal([]byte(auth["validBefore"].(string)), &until)
	data := DepositCalldata(cfg, deposit, 0, until, mustHex(auth["salt"].(string)), mustHex(auth["signature"].(string)))
	contract, _ := evm.ParseAddress(BatchContract)
	tx, err := rpc.Send(ctx, kb, 8453, contract, data)
	if err != nil {
		t.Fatalf("deposit: %v", err)
	}
	t.Logf("deposit tx %s", tx)
	bal, claimed, err := OnchainChannel(ctx, rpc, id)
	if err != nil || bal.Cmp(deposit) != 0 || claimed.Sign() != 0 {
		t.Fatalf("channel after deposit: balance %v claimed %v (%v)", bal, claimed, err)
	}

	// a voucher for 1000, as the wallet signs it for the first request; the contract verifies it
	vp, _ := VoucherPayload(k, o, cfg, big.NewInt(1000))
	sig := mustHex(vp["voucher"].(map[string]any)["signature"].(string))
	claim := ClaimCalldata(cfg, big.NewInt(1000), sig, big.NewInt(1000))
	tx, err = rpc.Send(ctx, kb, 8453, contract, claim)
	if err != nil {
		t.Fatalf("the contract rejected the wallet's voucher: %v", err)
	}
	t.Logf("claim tx %s", tx)
	bal, claimed, _ = OnchainChannel(ctx, rpc, id)
	if claimed.Int64() != 1000 {
		t.Fatalf("claimed %v, want 1000", claimed)
	}

	// cooperative refund of the unclaimed 2000
	tx, err = rpc.Send(ctx, kb, 8453, contract, RefundCalldata(cfg, big.NewInt(2000)))
	if err != nil {
		t.Fatalf("refund: %v", err)
	}
	t.Logf("refund tx %s", tx)
	time.Sleep(6 * time.Second) // let the public RPC catch up with the new block
	bal, claimed, _ = OnchainChannel(ctx, rpc, id)
	t.Logf("channel at the end: balance %v, totalClaimed %v", bal, claimed)
	if bal.Int64() != 1000 || claimed.Int64() != 1000 {
		t.Fatalf("after the refund the channel should hold exactly the claimed 1000, got balance %v claimed %v", bal, claimed)
	}
}
