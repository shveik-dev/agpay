package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/x402pay"
)

// The agpay.shveik.dev escrow: a custodial hold between two agents (see its /agents.md). The
// buyer's secret is chosen here, kept in deals.json (0600) and never sent anywhere except as the
// bearer of the buyer's own follow-up calls.

const defaultService = "https://agpay.shveik.dev"

type dealRec struct {
	Deal    string `json:"deal_id"`
	Secret  string `json:"secret"`
	Seller  string `json:"seller"`
	Amount  string `json:"amount_usd"`
	Service string `json:"service"`
	Created int64  `json:"created"`
}

var dealsMu sync.Mutex

func loadDeals(path string) map[string]dealRec {
	m := map[string]dealRec{}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func saveDeals(path string, m map[string]dealRec) error {
	b, _ := json.MarshalIndent(m, "", "  ")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func call(ctx context.Context, method, u string, bearer string, body any) (int, []byte, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, u, rd)
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	cl := &http.Client{Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, nil, &x402pay.Error{Code: "network_error", Message: err.Error(), Exit: x402pay.ExitNetwork, Retryable: true}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, nil
}

func apiResult(status int, b []byte) (any, error) {
	var v any
	if json.Unmarshal(b, &v) != nil {
		v = string(b)
	}
	if status >= 200 && status < 300 {
		return v, nil
	}
	msg := fmt.Sprintf("HTTP %d", status)
	code := "http_error"
	if m, ok := v.(map[string]any); ok {
		if e, ok := m["error"].(map[string]any); ok {
			if k, _ := e["kind"].(string); k != "" {
				code = k
			}
			if s, _ := e["message"].(string); s != "" {
				msg = s
			}
		}
	}
	exit := 1
	if status == 401 || status == 403 {
		exit = x402pay.ExitWallet
	}
	if status >= 500 || status == 429 {
		exit = x402pay.ExitNetwork
	}
	return nil, &x402pay.Error{Code: code, Message: msg, Exit: exit, Retryable: status >= 500 || status == 429}
}

func init() {
	register(&command{Name: "deal", Group: "agpay", Summary: "the agpay escrow between two agents: buyer create|status|confirm|dispute|statement|list, seller accept|deliver|refund|statement",
		Money: true, Secret: true,
		Example: "agpay deal create --seller 0x... --amount 5.00 --ref job-17 | agpay deal confirm dl_...",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			service := fs.String("service", "", "service origin (default $AGPAY_SERVICE_URL or "+defaultService+")")
			seller := fs.String("seller", "", "create: the seller's EVM address")
			amount := fs.String("amount", "", "create: dollars to hold for the seller, whole cents (0.50 .. 500.00)")
			ref := fs.String("ref", "", "create: a public reference (<= 200 chars)")
			deadline := fs.Int("deadline-hours", 0, "create: hours the seller has to deliver (1..720, default 168)")
			review := fs.Int("review-hours", 0, "create: hours the buyer has to review (48..336, default 168)")
			instant := fs.Bool("instant", false, "create: allow immediate delivery and early confirm")
			reason := fs.String("reason", "", "dispute: why (<= 500 chars)")
			text := fs.String("text", "", "statement: the text (<= 2000 chars)")
			as := fs.String("as", "buyer", "list or statement: buyer or seller")
			network := fs.String("network", "", "pay on this network (default base)")
			max := fs.String("max", "", "create: refuse if the total price exceeds this many dollars")
			key := fs.String("idempotency-key", "", "create: a retry with the same key never pays twice")
			return func(c *ctx) (any, error) {
				if len(c.Args) == 0 {
					return nil, usage("bad_args", "usage: agpay deal create|status|confirm|dispute|statement|list|accept|deliver|refund")
				}
				origin := strings.TrimRight(firstNonEmpty(*service, c.Env.env("AGPAY_SERVICE_URL"), defaultService), "/")
				act := c.Args[0]
				cctx, cancel := contextTimeout(c, 4*time.Minute)
				defer cancel()
				id := ""
				if act != "create" && act != "list" {
					if len(c.Args) != 2 {
						return nil, usage("bad_args", "usage: agpay deal %s DEAL_ID", act)
					}
					id = c.Args[1]
					if !strings.HasPrefix(id, "dl_") || strings.ContainsAny(id, "/?# ") {
						return nil, usage("bad_args", "%q is not a deal id", id)
					}
				}
				switch act {
				case "status":
					st, b, err := call(cctx, "GET", origin+"/v1/deals/"+id, "", nil)
					if err != nil {
						return nil, err
					}
					return apiResult(st, b)
				case "list":
					v, err := c.openVault()
					if err != nil {
						return nil, err
					}
					q := "buyer"
					if *as == "seller" {
						q = "seller"
					} else if *as != "buyer" {
						return nil, usage("bad_flags", "--as is buyer or seller")
					}
					st, b, err := call(cctx, "GET", origin+"/v1/deals?"+q+"="+url.QueryEscape(v.EVM.Hex()), "", nil)
					if err != nil {
						return nil, err
					}
					return apiResult(st, b)
				case "create":
					return createDeal(c, cctx, origin, *seller, *amount, *ref, *deadline, *review, *instant, *network, *max, *key)
				case "confirm", "dispute":
					d, ok := loadDeals(c.path("deals.json"))[id]
					if !ok {
						return nil, usage("unknown_deal", "this wallet holds no buyer secret for %s (it only knows deals it created)", id)
					}
					var body any
					if act == "dispute" {
						if *reason == "" {
							return nil, usage("bad_flags", "dispute needs --reason")
						}
						body = map[string]string{"reason": *reason}
					}
					st, b, err := call(cctx, "POST", origin+"/v1/deals/"+id+"/"+act, d.Secret, body)
					if err != nil {
						return nil, err
					}
					return apiResult(st, b)
				case "accept", "deliver", "refund":
					return sellerAction(c, cctx, origin, id, act, "")
				case "statement":
					if *text == "" {
						return nil, usage("bad_flags", "statement needs --text")
					}
					if *as == "seller" {
						return sellerAction(c, cctx, origin, id, "statement", *text)
					}
					d, ok := loadDeals(c.path("deals.json"))[id]
					if !ok {
						return nil, usage("unknown_deal", "this wallet holds no buyer secret for %s", id)
					}
					st, b, err := call(cctx, "POST", origin+"/v1/deals/"+id+"/statement", d.Secret, map[string]string{"text": *text})
					if err != nil {
						return nil, err
					}
					return apiResult(st, b)
				}
				return nil, usage("bad_args", "unknown deal action %q", act)
			}
		}})
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func createDeal(c *ctx, cctx context.Context, origin, seller, amount, ref string, deadline, review int, instant bool, network, max, key string) (any, error) {
	if seller == "" || amount == "" {
		return nil, usage("bad_flags", "create needs --seller and --amount")
	}
	if _, err := evm.ParseAddress(seller); err != nil {
		return nil, usage("bad_flags", "--seller: %v", err)
	}
	if n, err := chain.ParseUSD(amount); err != nil || n.Int64()%10000 != 0 {
		return nil, usage("bad_flags", "--amount must be whole cents, e.g. 5.00")
	}
	cl, v, err := c.client()
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(seller, v.EVM.Hex()) {
		return nil, usage("self_deal", "the seller cannot be this wallet")
	}
	sb := make([]byte, 16)
	rand.Read(sb)
	secret := "agp_" + hex.EncodeToString(sb)
	h := sha256.Sum256([]byte(secret))
	net := firstNonEmpty(network, "base")
	if n, ok := cl.Reg.Find(net); ok && n.V1 != "" {
		net = n.V1
	}
	body := map[string]any{"amount_usd": amount, "seller_address": seller, "network": net, "secret_hash": hex.EncodeToString(h[:])}
	if deadline > 0 {
		body["deadline_hours"] = deadline
	}
	if review > 0 {
		body["review_hours"] = review
	}
	if instant {
		body["instant"] = true
	}
	if ref != "" {
		body["ref"] = ref
	}
	bb, _ := json.Marshal(body)
	req := x402pay.Request{Method: "POST", URL: origin + "/x402/deal", Header: http.Header{}, Body: bb, Network: network, Scheme: "exact", Key: key}
	if max != "" {
		if req.MaxAtomic, err = chain.ParseUSD(max); err != nil {
			return nil, usage("bad_flags", "--max: %v", err)
		}
	}
	// the secret must survive a lost response: write it before the money moves
	dealsMu.Lock()
	defer dealsMu.Unlock()
	deals := loadDeals(c.path("deals.json"))
	pending := "pending_" + hex.EncodeToString(h[:4])
	deals[pending] = dealRec{Secret: secret, Seller: seller, Amount: amount, Service: origin, Created: time.Now().Unix()}
	if err := saveDeals(c.path("deals.json"), deals); err != nil {
		return nil, err
	}
	res, err := cl.Pay(cctx, req)
	if err != nil {
		if res == nil || res.SpendID == "" {
			delete(deals, pending)
			saveDeals(c.path("deals.json"), deals)
		}
		if res != nil {
			return nil, detailErr{asErr(err), receipt(res)}
		}
		return nil, err
	}
	var rec struct {
		DealID string `json:"deal_id"`
	}
	json.Unmarshal(res.Body, &rec)
	if rec.DealID == "" {
		return nil, &x402pay.Error{Code: "no_deal_id", Message: "the service paid but returned no deal id; the secret is kept under " + pending + " in deals.json", Exit: 1}
	}
	d := deals[pending]
	d.Deal = rec.DealID
	delete(deals, pending)
	deals[rec.DealID] = d
	if err := saveDeals(c.path("deals.json"), deals); err != nil {
		return nil, err
	}
	var rcpt any
	json.Unmarshal(res.Body, &rcpt)
	return map[string]any{"deal": rcpt, "payment": receipt(res), "secret_stored_in": c.path("deals.json"),
		"next": "act on the seller side only once the deal is `funded` (`agpay deal status " + rec.DealID + "`); the buyer then confirms with `agpay deal confirm`"}, nil
}

// sellerAction signs the exact text the service rebuilds (host, network, deal, action, amount,
// expiry [, data]) and posts it. The amount is read from the public deal record.
func sellerAction(c *ctx, cctx context.Context, origin, id, act, text string) (any, error) {
	v, err := c.openVault()
	if err != nil {
		return nil, err
	}
	st, b, err := call(cctx, "GET", origin+"/v1/deals/"+id, "", nil)
	if err != nil {
		return nil, err
	}
	dv, err := apiResult(st, b)
	if err != nil {
		return nil, err
	}
	m, _ := dv.(map[string]any)
	amt, _ := m["amount"].(float64)
	if amt == 0 {
		return nil, usage("bad_deal", "the deal record has no amount")
	}
	if who, _ := m["seller_address"].(string); !strings.EqualFold(who, v.EVM.Hex()) {
		return nil, usage("not_the_seller", "this wallet (%s) is not the seller of %s", v.EVM.Hex(), id)
	}
	u, _ := url.Parse(origin)
	host := u.Hostname()
	expires := c.Env.now().Add(8 * time.Minute).Unix()
	body := map[string]any{"address": v.EVM.Hex(), "expires": expires}
	data := ""
	if act == "statement" {
		sum := sha256.Sum256([]byte(text))
		data = hex.EncodeToString(sum[:])
		body["text"] = text
	}
	sig, err := evm.SignEth(v.Secrets.EVMPriv(), evm.PersonalHash([]byte(agpMessage(host, id, act, strconv.FormatInt(int64(amt), 10), expires, data))))
	if err != nil {
		return nil, err
	}
	body["signature"] = "0x" + hex.EncodeToString(sig)
	st, b, err = call(cctx, "POST", origin+"/v1/deals/"+id+"/"+act, "", body)
	if err != nil {
		return nil, err
	}
	return apiResult(st, b)
}

// agpMessage is the exact text the escrow rebuilds and verifies (docs/agpay-spec.md section 3):
// host, network, deal, action, amount and expiry, plus a data line for statements.
func agpMessage(host, deal, action, amount string, expires int64, data string) string {
	m := "AGP v1\nhost: " + host + "\nnetwork: eip155:8453\ndeal: " + deal + "\naction: " + action + "\namount: " + amount + "\nexpires: " + strconv.FormatInt(expires, 10)
	if data != "" {
		m += "\ndata: " + data
	}
	return m
}
