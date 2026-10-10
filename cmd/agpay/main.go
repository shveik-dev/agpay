// Command agpay is a wallet for AI agents: it holds USDC on Base, other EVM chains and Solana,
// pays x402 endpoints (exact, and batch-settlement channels on EVM) within owner-set limits, and
// drives the agpay.shveik.dev escrow. See README.md; `agpay describe` lists everything as JSON.
package main

import (
	"os"

	"github.com/shveik-dev/agpay/internal/app"
)

func main() {
	app.Harden()
	os.Exit(app.Run(&app.Env{Args: os.Args[1:], Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}))
}
