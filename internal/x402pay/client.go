package x402pay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/sol"
)

// Error carries a stable machine code, a hint for the agent and the process exit code.
type Error struct {
	Code      string
	Message   string
	Hint      string
	Exit      int
	Retryable bool
}

func (e *Error) Error() string { return e.Message }

func errf(code string, exit int, hint string, f string, a ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(f, a...), Hint: hint, Exit: exit}
}

const (
	ExitUsage   = 2
	ExitPolicy  = 3
	ExitPayment = 4
	ExitFunds   = 5
	ExitWallet  = 6
	ExitNetwork = 7
)

const maxBody = 16 << 20

type Client struct {
	Keys     Keys
	Reg      *chain.Registry
	Rules    policy.Rules
	Ledger   policy.Ledger
	Sessions Store
	HTTP     *http.Client
	Now      func() time.Time
}

type Request struct {
	Method    string
	URL       string
	Header    http.Header
	Body      []byte
	MaxAtomic *big.Int // per-call ceiling set by the caller, on top of the policy
	Network   string   // preferred network (CAIP-2 or name)
	Scheme    string   // exact | batch-settlement | "" (auto)
	DryRun    bool
	Key       string // idempotency key: a second call with the same key does not pay again
}

type Verdict struct {
	Scheme  string `json:"scheme"`
	Network string `json:"network"`
	Amount  string `json:"amount_atomic"`
	USD     string `json:"amount_usdc"`
	PayTo   string `json:"pay_to"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type Result struct {
	Status  int
	Header  http.Header
	Body    []byte
	Paid    bool
	Quote   []Verdict
	Chosen  *Verdict
	Settle  *SettleResponse
	SpendID string
	Channel string // batch-settlement channel id, when used
	Deposit string // atomic deposit sent with this payment, when any
	Resp402 *Required
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 240 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func loopback(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) send(ctx context.Context, r Request, header string, v1 bool) (*http.Response, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, r.Method, r.URL, bytes.NewReader(r.Body))
	if err != nil {
		return nil, nil, errf("bad_request", ExitUsage, "give a full https URL", "%v", err)
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if len(r.Body) > 0 && req.Header.Get("content-type") == "" {
		req.Header.Set("content-type", "application/json")
	}
	if header != "" {
		if v1 {
			req.Header.Set("X-PAYMENT", header)
		} else {
			req.Header.Set("PAYMENT-SIGNATURE", header)
		}
	}
	resp, err := c.http().Do(req)
	if err != nil {
		e := errf("network_error", ExitNetwork, "retry; nothing was signed before a response was read", "%v", err)
		e.Retryable = header == ""
		return nil, nil, e
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, nil, errf("network_error", ExitNetwork, "", "reading the response: %v", err)
	}
	if len(b) > maxBody {
		return nil, nil, errf("response_too_large", ExitNetwork, "the response is over 16 MB", "response too large")
	}
	return resp, b, nil
}

// Quote probes the URL without paying and judges every offer against the owner's rules.
func (c *Client) Quote(ctx context.Context, r Request) (*Result, *Required, []Offer, error) {
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" {
		return nil, nil, nil, errf("bad_request", ExitUsage, "give a full https URL", "not a URL: %q", r.URL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && (c.Rules.AllowHTTP || loopback(u.Host))) {
		return nil, nil, nil, errf("insecure_url", ExitPolicy, "payments only go over https (the owner can allow http in the policy)", "refusing to pay over %s", u.Scheme)
	}
	if !c.Rules.HostOK(u.Hostname()) {
		return nil, nil, nil, errf("host_not_allowed", ExitPolicy, "ask the owner to add the host to the policy", "the policy does not allow payments to %s", u.Hostname())
	}
	resp, body, err := c.send(ctx, r, "", false)
	if err != nil {
		return nil, nil, nil, err
	}
	res := &Result{Status: resp.StatusCode, Header: resp.Header, Body: body}
	if resp.StatusCode != http.StatusPaymentRequired {
		return res, nil, nil, nil
	}
	req, err := ParseRequired(resp.Header, body)
	if err != nil {
		return nil, nil, nil, errf("bad_402", ExitPayment, "the server answered 402 without x402 requirements", "%v", err)
	}
	res.Resp402 = req
	offers, skipped := req.Offers(c.Reg)
	for _, s := range skipped {
		res.Quote = append(res.Quote, Verdict{Reason: s})
	}
	for i := range offers {
		o := &offers[i]
		v := Verdict{Scheme: o.Scheme, Network: o.Network, Amount: o.Amount.String(), USD: o.Net.Format(o.Amount), PayTo: o.PayTo, Allowed: true}
		if reason := c.refuse(*o, r); reason != "" {
			v.Allowed, v.Reason = false, reason
		}
		res.Quote = append(res.Quote, v)
	}
	return res, req, offers, nil
}

func (c *Client) refuse(o Offer, r Request) string {
	if !c.Rules.NetworkOK(o.Network) {
		return "network not allowed by the policy"
	}
	if !c.Rules.SchemeOK(o.Scheme) {
		return "scheme not allowed by the policy"
	}
	if o.Net.Kind == "evm" {
		if a, err := evm.ParseAddress(o.PayTo); err != nil || a == (evm.Address{}) {
			return "payTo is not a usable address"
		}
	}
	if o.Net.Kind == "svm" {
		if a, err := sol.ParseAddress(o.PayTo); err != nil || a == (sol.Address{}) {
			return "payTo is not a usable address"
		}
	}
	if o.Net.Kind == "evm" && c.Keys.EVM == nil || o.Net.Kind == "svm" && c.Keys.Sol == nil {
		return "the wallet has no key for this network family"
	}
	if o.Amount.Cmp(c.Rules.Big(c.Rules.MaxPayment)) > 0 {
		return fmt.Sprintf("over the per-payment limit of %s", o.Net.Format(c.Rules.Big(c.Rules.MaxPayment)))
	}
	if r.MaxAtomic != nil && o.Amount.Cmp(r.MaxAtomic) > 0 {
		return fmt.Sprintf("over this call's --max of %s", o.Net.Format(r.MaxAtomic))
	}
	if o.Scheme == "batch-settlement" && o.Net.Kind != "evm" {
		return "batch-settlement is only implemented on EVM networks"
	}
	if o.Net.Kind == "svm" {
		if fp, _ := o.Extra["feePayer"].(string); fp == "" {
			return "offer has no extra.feePayer"
		} else if fp == c.Keys.SolAdr.String() {
			return "the fee payer is this wallet itself"
		}
	}
	return ""
}

// choose picks the cheapest allowed offer, preferring the caller's network and scheme.
func (c *Client) choose(offers []Offer, r Request) (*Offer, error) {
	var cand []Offer
	for _, o := range offers {
		if c.refuse(o, r) != "" {
			continue
		}
		if r.Network != "" {
			if n, ok := c.Reg.Find(r.Network); !ok || n.CAIP != o.Network {
				continue
			}
		}
		if r.Scheme != "" && o.Scheme != r.Scheme {
			continue
		}
		cand = append(cand, o)
	}
	if len(cand) == 0 {
		return nil, errf("no_acceptable_offer", ExitPolicy, "run `agpay quote` to see why each offer was refused", "none of the server's offers can be paid under the policy")
	}
	rank := func(o Offer) int { // exact before channels unless asked, then cheapest, EVM Base first
		s := 0
		if o.Scheme == "batch-settlement" && r.Scheme == "" {
			s += 1000
			if sess := c.openChannel(o); sess {
				s -= 2000 // an open channel with room is the cheapest way to pay
			}
		}
		if o.Network != "eip155:8453" {
			s++
		}
		return s
	}
	sort.SliceStable(cand, func(i, j int) bool {
		if ri, rj := rank(cand[i]), rank(cand[j]); ri != rj {
			return ri < rj
		}
		return cand[i].Amount.Cmp(cand[j].Amount) < 0
	})
	return &cand[0], nil
}

func (c *Client) openChannel(o Offer) bool {
	if o.Net.Kind != "evm" || c.Keys.EVM == nil {
		return false
	}
	cfg, err := BuildConfig(c.Keys, o)
	if err != nil {
		return false
	}
	s, _ := c.Sessions.Get(hexID(cfg.ChannelID(o.Net.ChainID)))
	if s == nil {
		return false
	}
	bal, _ := new(big.Int).SetString(s.Balance, 10)
	ch, _ := new(big.Int).SetString(s.Charged, 10)
	return bal != nil && ch != nil && new(big.Int).Add(ch, o.Amount).Cmp(bal) <= 0
}

func (c *Client) evmRPC(n chain.Net) *evm.RPC { return &evm.RPC{URLs: n.RPC} }
func (c *Client) solRPC(n chain.Net) *sol.RPC { return &sol.RPC{URLs: n.RPC} }

// Pay runs the whole flow: probe, choose, reserve the spend, sign, replay, record the outcome.
func (c *Client) Pay(ctx context.Context, r Request) (*Result, error) {
	if prev, err := c.Ledger.ByKey(r.Key); err != nil {
		return nil, errf("ledger_error", 1, "", "%v", err)
	} else if prev != nil && !r.DryRun {
		return nil, &Error{Code: "already_paid", Message: fmt.Sprintf("idempotency key %q already paid %s atomic USDC (spend %s, %s)", r.Key, prev.Amount, prev.ID, prev.Status),
			Hint: "use a new key to pay again; the first attempt's receipt is in `agpay history`", Exit: ExitPayment}
	}
	res, req, offers, err := c.Quote(ctx, r)
	if err != nil {
		return nil, err
	}
	if req == nil { // not a 402: nothing to pay
		return res, nil
	}
	o, err := c.choose(offers, r)
	if err != nil {
		return res, err
	}
	chosen := Verdict{Scheme: o.Scheme, Network: o.Network, Amount: o.Amount.String(), USD: o.Net.Format(o.Amount), PayTo: o.PayTo, Allowed: true}
	res.Chosen = &chosen
	if r.DryRun {
		return res, nil
	}
	if o.Net.Kind == "evm" && o.Scheme == "exact" {
		if bal, err := c.evmRPC(o.Net).BalanceOf(ctx, mustAddr(o.Asset), c.Keys.EVMAdr); err == nil && bal.Cmp(o.Amount) < 0 {
			return res, errf("insufficient_funds", ExitFunds, "fund the wallet address on "+o.Net.Name, "the wallet holds %s USDC on %s, the offer needs %s", o.Net.Format(bal), o.Net.Name, o.Net.Format(o.Amount))
		}
	}
	if o.Scheme == "batch-settlement" {
		return c.payBatch(ctx, r, res, req, *o)
	}
	var payload map[string]any
	var until int64
	switch o.Net.Kind {
	case "evm":
		payload, until, err = ExactEVM(c.Keys, *o, c.now())
	case "svm":
		payload, err = ExactSVM(ctx, c.solRPC(o.Net), c.Keys, *o)
		until = c.now().Unix() + 90 // a blockhash lives about that long
	}
	if err != nil {
		code := "sign_failed"
		exit := ExitPayment
		if strings.HasPrefix(err.Error(), "insufficient_funds") {
			code, exit = "insufficient_funds", ExitFunds
		}
		return res, errf(code, exit, "", "%v", err)
	}
	return c.submit(ctx, r, res, req, *o, payload, o.Amount, "exact", until)
}

func (c *Client) header(req *Required, o Offer, payload map[string]any) (string, error) {
	var body map[string]any
	if req.V1 {
		body = map[string]any{"x402Version": 1, "scheme": o.Scheme, "network": str(o.Raw, "network"), "payload": payload}
	} else {
		body = map[string]any{"x402Version": req.Version, "accepted": o.Raw, "payload": payload}
		if req.Resource != nil {
			body["resource"] = req.Resource
		}
		if req.Extensions != nil {
			body["extensions"] = req.Extensions
		}
	}
	b, err := json.Marshal(body)
	return base64.StdEncoding.EncodeToString(b), err
}

// submit reserves the spend, sends the signed payment and settles the books.
func (c *Client) submit(ctx context.Context, r Request, res *Result, req *Required, o Offer, payload map[string]any, spend *big.Int, kind string, until int64) (*Result, error) {
	u, _ := url.Parse(r.URL)
	e := policy.Entry{ID: policy.NewID(), Host: u.Host, URL: r.URL, Network: o.Network, Scheme: o.Scheme, Kind: kind, Amount: spend.String(), Asset: o.Asset, ValidUntil: until, Key: r.Key}
	if err := c.Ledger.Reserve(c.Rules, e, c.now()); err != nil {
		var le *policy.LimitError
		if errors.As(err, &le) {
			return res, errf("limit_exceeded", ExitPolicy, "ask the owner to raise the limit, or wait for the 24 h window", "%v", err)
		}
		return res, errf("ledger_error", 1, "", "%v", err)
	}
	res.SpendID = e.ID
	h, err := c.header(req, o, payload)
	if err != nil {
		c.Ledger.Finish(e.ID, "failed", "", err.Error())
		return res, errf("sign_failed", ExitPayment, "", "%v", err)
	}
	resp, body, err := c.send(ctx, r, h, req.V1)
	if err != nil {
		// the request may have reached the server: leave the reservation to expire with the authorization
		return res, err
	}
	res.Status, res.Header, res.Body = resp.StatusCode, resp.Header, body
	res.Settle = ParseSettle(resp.Header)
	ok := resp.StatusCode >= 200 && resp.StatusCode < 300 && (res.Settle == nil || res.Settle.Success)
	if ok {
		res.Paid = true
		tx := ""
		if res.Settle != nil {
			tx = res.Settle.Transaction
		}
		c.Ledger.Finish(e.ID, "settled", tx, "")
		return res, nil
	}
	if resp.StatusCode >= 500 && resp.StatusCode != 503 || resp.StatusCode == 504 {
		return res, errf("payment_unconfirmed", ExitPayment, "the server failed after receiving the payment; check `agpay history` and the receipt before paying again", "HTTP %d after signing", resp.StatusCode)
	}
	reason := ""
	if res.Settle != nil {
		reason = res.Settle.ErrorReason
	}
	if reason == "" {
		if p, err := ParseRequired(resp.Header, body); err == nil {
			reason = p.Error
		}
	}
	if reason == "" {
		reason = snippet(body)
	}
	c.Ledger.Finish(e.ID, "failed", "", reason)
	res.Resp402, _ = ParseRequired(resp.Header, body)
	return res, errf("payment_rejected", ExitPayment, "nothing was charged; the offer may have changed, run the call again", "HTTP %d: %s", resp.StatusCode, firstNonEmpty(reason, "payment not accepted"))
}

// snippet is a short, single-line excerpt of a response body for error messages.
func snippet(b []byte) string {
	s := strings.Join(strings.Fields(string(b)), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func mustAddr(s string) evm.Address { a, _ := evm.ParseAddress(s); return a }

// payBatch pays through a batch-settlement channel: a voucher when the channel has room, a deposit
// (plus voucher) when it must be opened or topped up.
func (c *Client) payBatch(ctx context.Context, r Request, res *Result, req *Required, o Offer) (*Result, error) {
	cfg, err := BuildConfig(c.Keys, o)
	if err != nil {
		return res, errf("bad_offer", ExitPayment, "", "%v", err)
	}
	id := cfg.ChannelID(o.Net.ChainID)
	rpc := c.evmRPC(o.Net)
	for attempt := 0; attempt < 2; attempt++ {
		sess, _ := c.Sessions.Get(hexID(id))
		if sess == nil {
			bal, claimed, err := OnchainChannel(ctx, rpc, id)
			if err != nil {
				return res, errf("rpc_error", ExitNetwork, "retry", "reading the channel: %v", err)
			}
			sess = &Session{ChannelID: hexID(id), Network: o.Net.CAIP, Receiver: cfg.Receiver.Hex(), Balance: bal.String(), Charged: claimed.String()}
			u, _ := url.Parse(r.URL)
			sess.Host = u.Host
		}
		balance, _ := new(big.Int).SetString(sess.Balance, 10)
		charged, _ := new(big.Int).SetString(sess.Charged, 10)
		next := new(big.Int).Add(charged, o.Amount)
		var payload map[string]any
		var spend *big.Int
		kind := "voucher"
		var depositAmt *big.Int
		var until int64
		if balance.Sign() == 0 || next.Cmp(balance) > 0 {
			needed := new(big.Int).Sub(next, balance)
			depositAmt = DepositTarget(o, needed)
			if max := c.Rules.Big(c.Rules.MaxDeposit); depositAmt.Cmp(max) > 0 {
				if needed.Cmp(max) > 0 {
					return res, errf("limit_exceeded", ExitPolicy, "ask the owner to raise max_deposit", "the channel needs a %s deposit, the policy allows %s", o.Net.Format(needed), o.Net.Format(max))
				}
				depositAmt = max
			}
			if bal, err := rpc.BalanceOf(ctx, mustAddr(o.Asset), c.Keys.EVMAdr); err == nil && bal.Cmp(depositAmt) < 0 {
				return res, errf("insufficient_funds", ExitFunds, "fund the wallet address on "+o.Net.Name, "a deposit of %s needs funds, the wallet holds %s", o.Net.Format(depositAmt), o.Net.Format(bal))
			}
			payload, err = DepositPayload(c.Keys, o, cfg, depositAmt, next, c.now())
			spend, kind = depositAmt, "deposit"
			until = c.now().Unix() + o.Timeout
		} else {
			payload, err = VoucherPayload(c.Keys, o, cfg, next)
			spend = o.Amount
		}
		if err != nil {
			return res, errf("sign_failed", ExitPayment, "", "%v", err)
		}
		res.Channel = hexID(id)
		if depositAmt != nil {
			res.Deposit = depositAmt.String()
		}
		out, err := c.submit(ctx, r, res, req, o, payload, spend, kind, until)
		if err == nil && out.Paid {
			c.afterBatch(sess, o, out, depositAmt)
			return out, nil
		}
		// a corrective 402 carries the server's view of the channel: resync once and retry
		var pe *Error
		if attempt == 0 && errors.As(err, &pe) && pe.Code == "payment_rejected" && out != nil && out.Resp402 != nil &&
			(strings.Contains(out.Resp402.Error, "cumulative_amount_mismatch") || strings.Contains(out.Resp402.Error, "cumulative_below_claimed")) {
			for _, a := range out.Resp402.Accepts {
				if str(a, "scheme") == "batch-settlement" {
					o2 := o
					o2.Extra, _ = a["extra"].(map[string]any)
					if _, rerr := Resync(ctx, rpc, c.Keys, o2, cfg, c.Sessions); rerr != nil {
						return out, errf("resync_failed", ExitNetwork, "", "%v", rerr)
					}
					break
				}
			}
			continue
		}
		return out, err
	}
	return res, errf("payment_rejected", ExitPayment, "", "the channel could not be brought back in sync")
}

// afterBatch updates the local session from the wallet's own state plus the (untrusted, capped)
// chargedAmount of the settle response; it never copies the server's channelState.
func (c *Client) afterBatch(sess *Session, o Offer, out *Result, deposit *big.Int) {
	charge := new(big.Int)
	if out.Settle != nil && out.Settle.Extra != nil {
		if s, ok := out.Settle.Extra["chargedAmount"].(string); ok {
			if v, ok := new(big.Int).SetString(s, 10); ok && v.Sign() >= 0 && v.Cmp(o.Amount) <= 0 {
				charge = v
			}
		}
	}
	charged, _ := new(big.Int).SetString(sess.Charged, 10)
	balance, _ := new(big.Int).SetString(sess.Balance, 10)
	sess.Charged = new(big.Int).Add(charged, charge).String()
	if deposit != nil {
		sess.Balance = new(big.Int).Add(balance, deposit).String()
	}
	c.Sessions.Put(*sess)
}

// Refund asks the channel's server for a cooperative refund (zero-charge voucher; amount nil = all).
func (c *Client) Refund(ctx context.Context, r Request, amount *big.Int) (*Result, error) {
	res, req, offers, err := c.Quote(ctx, r)
	if err != nil {
		return nil, err
	}
	if req == nil {
		return res, errf("no_channel_offer", ExitPayment, "", "the URL did not answer 402")
	}
	var o *Offer
	for i := range offers {
		if offers[i].Scheme == "batch-settlement" && c.refuse(offers[i], r) == "" {
			o = &offers[i]
			break
		}
	}
	if o == nil {
		return res, errf("no_channel_offer", ExitPayment, "", "the server offers no batch-settlement channel for this URL")
	}
	cfg, err := BuildConfig(c.Keys, *o)
	if err != nil {
		return res, errf("bad_offer", ExitPayment, "", "%v", err)
	}
	id := cfg.ChannelID(o.Net.ChainID)
	sess, _ := c.Sessions.Get(hexID(id))
	rpc := c.evmRPC(o.Net)
	if sess == nil {
		bal, claimed, err := OnchainChannel(ctx, rpc, id)
		if err != nil {
			return res, errf("rpc_error", ExitNetwork, "", "%v", err)
		}
		sess = &Session{ChannelID: hexID(id), Network: o.Net.CAIP, Receiver: cfg.Receiver.Hex(), Balance: bal.String(), Charged: claimed.String()}
	}
	charged, _ := new(big.Int).SetString(sess.Charged, 10)
	balance, _ := new(big.Int).SetString(sess.Balance, 10)
	if balance.Cmp(charged) <= 0 {
		return res, errf("nothing_to_refund", ExitPayment, "", "the channel holds %s and %s is charged", balance, charged)
	}
	payload, err := RefundPayload(c.Keys, *o, cfg, charged, amount)
	if err != nil {
		return res, errf("sign_failed", ExitPayment, "", "%v", err)
	}
	h, _ := c.header(req, *o, payload)
	resp, body, err := c.send(ctx, r, h, false)
	if err != nil {
		return res, err
	}
	res.Status, res.Header, res.Body, res.Channel = resp.StatusCode, resp.Header, body, hexID(id)
	res.Settle = ParseSettle(resp.Header)
	if res.Settle == nil || !res.Settle.Success {
		reason := ""
		if res.Settle != nil {
			reason = res.Settle.ErrorReason
		}
		if p, err := ParseRequired(resp.Header, body); err == nil && reason == "" {
			reason = p.Error
		}
		return res, errf("refund_failed", ExitPayment, "", "the server did not refund: %s", firstNonEmpty(reason, fmt.Sprintf("HTTP %d", resp.StatusCode)))
	}
	res.Paid = true
	refunded, ok := new(big.Int).SetString(res.Settle.Amount, 10)
	if !ok || (amount != nil && refunded.Cmp(amount) > 0) {
		refunded = amount
	}
	if amount == nil || refunded == nil || refunded.Cmp(new(big.Int).Sub(balance, charged)) >= 0 {
		c.Sessions.Delete(hexID(id))
	} else {
		sess.Balance = new(big.Int).Sub(balance, refunded).String()
		c.Sessions.Put(*sess)
	}
	return res, nil
}
