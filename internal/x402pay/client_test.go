package x402pay

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/policy"
)

// fakeRPC answers eth_call for balanceOf (a large balance) and channels(bytes32).
func fakeRPC(t *testing.T, balance, claimed int64) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var q struct {
			Method string
			Params []json.RawMessage
		}
		json.NewDecoder(r.Body).Decode(&q)
		out := "0x" + strings.Repeat("0", 63) + "f" // balanceOf: 15... small
		if q.Method == "eth_call" {
			var call map[string]string
			json.Unmarshal(q.Params[0], &call)
			if strings.HasPrefix(call["data"], "0x"+hex.EncodeToString(evm.Keccak([]byte("channels(bytes32)"))[:4])) {
				out = fmt.Sprintf("0x%064x%064x", balance, claimed)
			} else {
				out = fmt.Sprintf("0x%064x", 1_000_000_000)
			}
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%q}`, out)
	}))
}

func testClient(t *testing.T, rpcURL string) (*Client, chain.Net) {
	n := chain.Net{CAIP: "eip155:8453", Name: "Base", V1: "base", Kind: "evm", ChainID: 8453, USDC: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", Decimals: 6, RPC: []string{rpcURL}}
	dir := t.TempDir()
	return &Client{Keys: testKeys(t), Reg: chain.New(n), Rules: policy.Defaults(), Ledger: policy.Ledger{Path: dir + "/spend.jsonl"}, Sessions: Store{Path: dir + "/ch.json"}}, n
}

func required(accepts ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"x402Version": 2, "accepts": accepts, "resource": map[string]any{"url": "x"}})
	return base64.StdEncoding.EncodeToString(b)
}

func exactOffer(amount string) map[string]any {
	return map[string]any{"scheme": "exact", "network": "eip155:8453", "amount": amount, "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
		"payTo": "0xbBa594F5549392DF7A8182049291b605948F5F86", "maxTimeoutSeconds": float64(120), "extra": map[string]any{"name": "USD Coin", "version": "2"}}
}

func TestPayExactEVM(t *testing.T) {
	rpc := fakeRPC(t, 0, 0)
	defer rpc.Close()
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("PAYMENT-SIGNATURE"); h != "" {
			b, _ := base64.StdEncoding.DecodeString(h)
			json.Unmarshal(b, &got)
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString([]byte(`{"success":true,"transaction":"0xabc","network":"eip155:8453"}`)))
			w.Write([]byte(`{"hello":"world"}`))
			return
		}
		w.Header().Set("PAYMENT-REQUIRED", required(exactOffer("31665")))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	c, n := testClient(t, rpc.URL)
	res, err := c.Pay(t.Context(), Request{Method: "POST", URL: srv.URL + "/x", Body: []byte(`{}`)})
	if err != nil || !res.Paid || string(res.Body) != `{"hello":"world"}` {
		t.Fatalf("%v %+v", err, res)
	}
	// the signed authorization must recover to the wallet
	auth := got["payload"].(map[string]any)["authorization"].(map[string]any)
	sig := mustHex(got["payload"].(map[string]any)["signature"].(string))
	from, to := mustAddr(auth["from"].(string)), mustAddr(auth["to"].(string))
	val, _ := new(big.Int).SetString(auth["value"].(string), 10)
	after, _ := new(big.Int).SetString(auth["validAfter"].(string), 10)
	before, _ := new(big.Int).SetString(auth["validBefore"].(string), 10)
	var nonce [32]byte
	copy(nonce[:], mustHex(auth["nonce"].(string)))
	d := evm.AuthDigest(evm.Domain{Name: "USD Coin", Version: "2", ChainID: big.NewInt(8453), Contract: mustAddr(n.USDC)}, evm.Auth{From: from, To: to, Value: val, ValidAfter: after, Until: before, Nonce: nonce})
	who, err := evm.RecoverEth(d, sig)
	if err != nil || who != c.Keys.EVMAdr || val.String() != "31665" {
		t.Fatal("signature", who, err)
	}
	if got["x402Version"].(float64) != 2 || got["accepted"] == nil || got["resource"] == nil {
		t.Fatalf("envelope %v", got)
	}
	if spent, _ := c.Ledger.Spent(time.Now()); spent.String() != "31665" {
		t.Fatal("ledger", spent)
	}
}

func TestPayRefusesOverLimitAndUnknownAsset(t *testing.T) {
	rpc := fakeRPC(t, 0, 0)
	defer rpc.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			t.Error("a payment was signed")
		}
		bad := exactOffer("100")
		bad["asset"] = "0x000000000000000000000000000000000000dEaD" // not Base USDC
		w.Header().Set("PAYMENT-REQUIRED", required(exactOffer("1000001"), bad))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	c, _ := testClient(t, rpc.URL)
	_, err := c.Pay(t.Context(), Request{Method: "GET", URL: srv.URL})
	if e, ok := err.(*Error); !ok || e.Code != "no_acceptable_offer" || e.Exit != ExitPolicy {
		t.Fatalf("%v", err)
	}
	res, _, _, _ := c.Quote(t.Context(), Request{Method: "GET", URL: srv.URL})
	if len(res.Quote) != 2 || res.Quote[0].Allowed && res.Quote[1].Allowed {
		t.Fatalf("%+v", res.Quote)
	}
}

func TestPayRefusesPlainHTTPToRemoteHost(t *testing.T) {
	c, _ := testClient(t, "http://127.0.0.1:1")
	_, err := c.Pay(t.Context(), Request{Method: "GET", URL: "http://example.com/x"})
	if e, ok := err.(*Error); !ok || e.Code != "insecure_url" {
		t.Fatal(err)
	}
}

func TestBatchVoucherThenDeposit(t *testing.T) {
	rpc := fakeRPC(t, 0, 0) // a channel that does not exist yet
	defer rpc.Close()
	var payloads []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("PAYMENT-SIGNATURE"); h != "" {
			b, _ := base64.StdEncoding.DecodeString(h)
			var p map[string]any
			json.Unmarshal(b, &p)
			payloads = append(payloads, p["payload"].(map[string]any))
			w.Header().Set("PAYMENT-RESPONSE", base64.StdEncoding.EncodeToString([]byte(`{"success":true,"extra":{"chargedAmount":"700"}}`)))
			w.Write([]byte("ok"))
			return
		}
		o := exactOffer("1000")
		o["scheme"] = "batch-settlement"
		o["extra"] = map[string]any{"receiverAuthorizer": "0x2222222222222222222222222222222222222222", "withdrawDelay": float64(900), "name": "USD Coin", "version": "2", "minDeposit": "3000"}
		w.Header().Set("PAYMENT-REQUIRED", required(o))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	c, _ := testClient(t, rpc.URL)
	for i := 0; i < 4; i++ {
		if _, err := c.Pay(t.Context(), Request{Method: "GET", URL: srv.URL, Scheme: "batch-settlement"}); err != nil {
			t.Fatal(i, err)
		}
	}
	types := []string{}
	for _, p := range payloads {
		types = append(types, p["type"].(string))
	}
	// 3000 deposit covers: deposit+voucher(1000), then the server charged 700 each time:
	// cumulative asked 1000, 1700, 2400, then 3100 > 3000 balance -> top-up deposit
	want := "deposit,voucher,voucher,deposit"
	if strings.Join(types, ",") != want {
		t.Fatalf("got %v want %s", types, want)
	}
	v := payloads[2]["voucher"].(map[string]any)
	if v["maxClaimableAmount"] != "2400" {
		t.Fatalf("cumulative %v", v["maxClaimableAmount"])
	}
}

func TestHostileOffersAreRefused(t *testing.T) {
	rpc := fakeRPC(t, 0, 0)
	defer rpc.Close()
	cases := map[string]func(o map[string]any){
		"zero payTo":      func(o map[string]any) { o["payTo"] = "0x0000000000000000000000000000000000000000" },
		"garbage payTo":   func(o map[string]any) { o["payTo"] = "not an address" },
		"negative amount": func(o map[string]any) { o["amount"] = "-5" },
		"plus amount":     func(o map[string]any) { o["amount"] = "+5" },
		"float amount":    func(o map[string]any) { o["amount"] = "1.5" },
		"huge amount":     func(o map[string]any) { o["amount"] = "99999999999999999999999999999" },
		"wrong asset":     func(o map[string]any) { o["asset"] = "0xdAC17F958D2ee523a2206206994597C13D831ec7" },
		"unknown network": func(o map[string]any) { o["network"] = "eip155:99999" },
		"permit2 transfer": func(o map[string]any) {
			o["extra"] = map[string]any{"assetTransferMethod": "permit2", "name": "USD Coin", "version": "2"}
		},
		"missing eip712": func(o map[string]any) { o["extra"] = map[string]any{} },
		"unknown scheme": func(o map[string]any) { o["scheme"] = "upto" },
	}
	for name, mutate := range cases {
		o := exactOffer("1000")
		mutate(o)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("PAYMENT-SIGNATURE") != "" {
				t.Errorf("%s: a payment was sent", name)
			}
			w.Header().Set("PAYMENT-REQUIRED", required(o))
			w.WriteHeader(402)
		}))
		c, _ := testClient(t, rpc.URL)
		if _, err := c.Pay(t.Context(), Request{Method: "GET", URL: srv.URL}); err == nil {
			t.Errorf("%s: paid", name)
		}
		srv.Close()
	}
}

func TestAuthorizationLifetimeIsCapped(t *testing.T) {
	k := testKeys(t)
	o := testOffer()
	o.Timeout = 31_536_000 // a hostile server asks for a year
	_, before, err := ExactEVM(k, o, time.Unix(1_800_000_000, 0))
	if err != nil || before-1_800_000_000 > maxValidity {
		t.Fatal(before, err)
	}
}

func TestRedirectIsNotFollowedWithPayment(t *testing.T) {
	rpc := fakeRPC(t, 0, 0)
	defer rpc.Close()
	var hitEvil bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hitEvil = true }))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			http.Redirect(w, r, evil.URL, http.StatusFound)
			return
		}
		w.Header().Set("PAYMENT-REQUIRED", required(exactOffer("1000")))
		w.WriteHeader(402)
	}))
	defer srv.Close()
	c, _ := testClient(t, rpc.URL)
	c.Pay(t.Context(), Request{Method: "GET", URL: srv.URL})
	if hitEvil {
		t.Fatal("followed a redirect carrying the payment")
	}
}
