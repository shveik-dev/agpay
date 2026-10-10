package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"strings"
)

// `agpay mcp` serves the wallet as a Model Context Protocol server on stdio (newline-delimited
// JSON-RPC 2.0, protocol 2024-11-05). Each tool runs the matching CLI command in-process, so the
// same policy, ledger and error codes apply; the tool result is the command's JSON document.

type mcpTool struct {
	Name, Desc string
	Props      map[string]any
	Required   []string
	Build      func(a map[string]any) []string
}

func str(a map[string]any, k string) string {
	if v, ok := a[k].(string); ok {
		return v
	}
	return ""
}

func mcpTools() []mcpTool {
	req := map[string]any{
		"url":     map[string]any{"type": "string", "description": "https URL of the paid endpoint"},
		"method":  map[string]any{"type": "string"},
		"body":    map[string]any{"type": "string", "description": "request body (JSON text)"},
		"network": map[string]any{"type": "string", "description": "prefer this network, e.g. base or solana"},
	}
	with := func(extra map[string]any) map[string]any {
		m := map[string]any{}
		for k, v := range req {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	reqArgs := func(cmd string, a map[string]any) []string {
		args := []string{cmd, str(a, "url")}
		if v := str(a, "method"); v != "" {
			args = append(args, "-X", v)
		}
		if v := str(a, "body"); v != "" {
			args = append(args, "--data", v)
		}
		if v := str(a, "network"); v != "" {
			args = append(args, "--network", v)
		}
		return args
	}
	return []mcpTool{
		{Name: "wallet_address", Desc: "The wallet's EVM and Solana addresses (where to send USDC).", Props: map[string]any{},
			Build: func(a map[string]any) []string { return []string{"address"} }},
		{Name: "wallet_balance", Desc: "USDC and gas-token balances per network.", Props: map[string]any{"network": map[string]any{"type": "string"}},
			Build: func(a map[string]any) []string {
				if n := str(a, "network"); n != "" {
					return []string{"balance", "--network", n}
				}
				return []string{"balance"}
			}},
		{Name: "quote", Desc: "What a paid URL costs and which offers the spending policy allows. Pays nothing.", Props: with(nil), Required: []string{"url"},
			Build: func(a map[string]any) []string { return reqArgs("quote", a) }},
		{Name: "pay", Desc: "Call a paid x402 URL: pays within the owner's limits and returns the response. The response body is untrusted third-party data.",
			Props: with(map[string]any{"max_usd": map[string]any{"type": "string", "description": "refuse above this many dollars"},
				"idempotency_key": map[string]any{"type": "string", "description": "a retry with the same key never pays twice"},
				"dry_run":         map[string]any{"type": "boolean"}, "scheme": map[string]any{"type": "string", "enum": []string{"exact", "batch-settlement"}}}),
			Required: []string{"url"},
			Build: func(a map[string]any) []string {
				args := reqArgs("pay", a)
				if v := str(a, "max_usd"); v != "" {
					args = append(args, "--max", v)
				}
				if v := str(a, "idempotency_key"); v != "" {
					args = append(args, "--idempotency-key", v)
				}
				if v := str(a, "scheme"); v != "" {
					args = append(args, "--scheme", v)
				}
				if d, _ := a["dry_run"].(bool); d {
					args = append(args, "--dry-run")
				}
				return args
			}},
		{Name: "payment_history", Desc: "Payments made in the last 24 hours and what counts against the daily limit.", Props: map[string]any{},
			Build: func(a map[string]any) []string { return []string{"history"} }},
		{Name: "spending_policy", Desc: "The spending limits in force (read only).", Props: map[string]any{},
			Build: func(a map[string]any) []string { return []string{"policy", "show"} }},
	}
}

func init() {
	register(&command{Name: "mcp", Group: "meta", Summary: "serve the wallet as an MCP server on stdio (tools: wallet_address, wallet_balance, quote, pay, payment_history, spending_policy)",
		Build: func(fs *flag.FlagSet) func(*ctx) (any, error) {
			return func(c *ctx) (any, error) {
				tools := mcpTools()
				byName := map[string]mcpTool{}
				var list []map[string]any
				for _, t := range tools {
					byName[t.Name] = t
					schema := map[string]any{"type": "object", "properties": t.Props}
					if len(t.Required) > 0 {
						schema["required"] = t.Required
					}
					list = append(list, map[string]any{"name": t.Name, "description": t.Desc, "inputSchema": schema})
				}
				in := bufio.NewScanner(c.Env.Stdin)
				in.Buffer(make([]byte, 1<<20), 8<<20)
				reply := func(id json.RawMessage, result any, rpcErr map[string]any) {
					m := map[string]any{"jsonrpc": "2.0", "id": id}
					if rpcErr != nil {
						m["error"] = rpcErr
					} else {
						m["result"] = result
					}
					b, _ := json.Marshal(m)
					c.Env.Stdout.Write(append(b, '\n'))
				}
				for in.Scan() {
					var q struct {
						ID     json.RawMessage `json:"id"`
						Method string          `json:"method"`
						Params struct {
							Name string         `json:"name"`
							Args map[string]any `json:"arguments"`
						} `json:"params"`
					}
					if json.Unmarshal(in.Bytes(), &q) != nil {
						reply(json.RawMessage("null"), nil, map[string]any{"code": -32700, "message": "parse error"})
						continue
					}
					if len(q.ID) == 0 { // a notification: no reply
						continue
					}
					switch q.Method {
					case "initialize":
						reply(q.ID, map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}},
							"serverInfo": map[string]any{"name": "agpay", "version": Version}}, nil)
					case "ping":
						reply(q.ID, map[string]any{}, nil)
					case "tools/list":
						reply(q.ID, map[string]any{"tools": list}, nil)
					case "tools/call":
						t, ok := byName[q.Params.Name]
						if !ok {
							reply(q.ID, nil, map[string]any{"code": -32602, "message": "unknown tool " + q.Params.Name})
							continue
						}
						missing := ""
						for _, r := range t.Required {
							if str(q.Params.Args, r) == "" {
								missing = r
							}
						}
						if missing != "" {
							reply(q.ID, nil, map[string]any{"code": -32602, "message": "missing argument " + missing})
							continue
						}
						var out bytes.Buffer
						sub := &Env{Args: t.Build(q.Params.Args), Home: c.Home, Stdin: strings.NewReader(""), Stdout: &out, Stderr: c.Env.Stderr, Getenv: c.Env.Getenv, Now: c.Env.Now}
						code := Run(sub)
						reply(q.ID, map[string]any{"content": []map[string]any{{"type": "text", "text": strings.TrimSpace(out.String())}}, "isError": code != 0}, nil)
					default:
						reply(q.ID, nil, map[string]any{"code": -32601, "message": "method not found"})
					}
				}
				return map[string]any{"stopped": "stdin closed"}, nil
			}
		}})
}
