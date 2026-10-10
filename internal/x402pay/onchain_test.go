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

// TestDepositAgainstTheRealContract simulates (eth_call, nothing is sent or spent) the deposit the
// wallet signs against the canonical x402BatchSettlement contract on Base mainnet. It runs only
// when AGPAY_ONCHAIN_TEST_KEY holds a funded wallet's key; the contract itself checks the channel
// id, the ERC-3009 nonce binding and our signature.
func TestDepositAgainstTheRealContract(t *testing.T) {
	keyHex := os.Getenv("AGPAY_ONCHAIN_TEST_KEY")
	if keyHex == "" {
		t.Skip("set AGPAY_ONCHAIN_TEST_KEY to run against Base mainnet (eth_call only)")
	}
	kb, _ := hex.DecodeString(strings.TrimPrefix(keyHex, "0x"))
	addr, err := evm.AddressOf(kb)
	if err != nil {
		t.Fatal(err)
	}
	k := Keys{EVM: kb, EVMAdr: addr}
	n, _ := chain.Builtin().Find("eip155:8453")
	o := Offer{Scheme: "batch-settlement", Network: n.CAIP, Net: n, Amount: big.NewInt(1000), Asset: n.USDC,
		PayTo: "0x1111111111111111111111111111111111111111", Timeout: 600,
		Extra: map[string]any{"receiverAuthorizer": "0x2222222222222222222222222222222222222222", "withdrawDelay": float64(900), "name": "USD Coin", "version": "2"}}
	cfg, err := BuildConfig(k, o)
	if err != nil {
		t.Fatal(err)
	}
	p, err := DepositPayload(k, o, cfg, big.NewInt(5000), big.NewInt(1000), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	auth := p["deposit"].(map[string]any)["authorization"].(map[string]any)["erc3009Authorization"].(map[string]any)
	sig := mustHex(auth["signature"].(string))
	salt := mustHex(auth["salt"].(string))
	var until int64
	json.Unmarshal([]byte(auth["validBefore"].(string)), &until)
	data := DepositCalldata(cfg, big.NewInt(5000), 0, until, salt, sig)

	rpc := &evm.RPC{URLs: n.RPC}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code, err := rpc.Call(ctx, "eth_getCode", BatchContract, "latest")
	if err != nil || len(code) < 100 {
		t.Fatalf("x402BatchSettlement is not deployed at the canonical address on Base: %v %s", err, code)
	}
	// anyone may submit a deposit; simulate it from the facilitator-like caller (the wallet itself)
	res, err := rpc.Call(ctx, "eth_call", map[string]string{"from": addr.Hex(), "to": BatchContract, "data": "0x" + hex.EncodeToString(data)}, "latest")
	if err != nil {
		t.Fatalf("the contract rejected the deposit the wallet signed: %v", err)
	}
	// the same call with a different salt breaks the nonce binding and must be refused: the
	// simulation is a real check, not a call that always succeeds
	badSalt := append([]byte(nil), salt...)
	badSalt[0] ^= 1
	bad := DepositCalldata(cfg, big.NewInt(5000), 0, until, badSalt, sig)
	if _, err := rpc.Call(ctx, "eth_call", map[string]string{"from": addr.Hex(), "to": BatchContract, "data": "0x" + hex.EncodeToString(bad)}, "latest"); err == nil {
		t.Fatal("the contract accepted a deposit with a broken nonce binding")
	}
	t.Logf("deposit simulation accepted by the canonical contract: result %s", res)
}
