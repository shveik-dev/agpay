# Live test log

What was run for real, so the claims in the README can be checked. Amounts are USDC. Transaction hashes are on Base unless noted.

## exact

| Date | Network | Against | Result |
|---|---|---|---|
| 2026-10-10 | Base | an x402 data API | settled, 0.022545, tx `0x60a7…c320e` |
| 2026-10-10 | Solana | the same API | settled, 0.01335 (SPL `TransferChecked` + memo, fee payer co-signed by the facilitator) |
| 2026-10-10 | Polygon | the same API | settled, 0.01275, tx `0x41ea…0b24` |

Payments were repeated from a second wallet after a key rotation and from a freshly created wallet, with the default policy.

## batch-settlement (EVM)

1. **Hand-driven channel on Base mainnet** (`go test ./internal/x402pay -run Live`, needs `AGPAY_LIVE_KEY`): a deposit of 0.003 through the canonical
   `x402BatchSettlement` contract with an ERC-3009 `receiveWithAuthorization` to the deposit collector, a signed voucher the contract accepted in a real `claim`,
   and a cooperative `refund` of the rest. After the refund the channel held exactly the claimed amount.
2. **Contract simulation** (`-run RealContract`, `eth_call` only): the signed deposit is accepted; the same call with a changed salt is refused.
3. **Production server, 2026-10-10** (a proxy that runs Actors, `POST /api-proxy/actors/{id}/runs?amount=1&currency=usd`):
   - first call: deposit of 3.00 (3x the ceiling) in tx `0x9b22…9c50` plus a 1.00 voucher; receipt returned at once; the result was read once after a 202;
   - the server charged the real cost later: 0.006412 of the 1.00 ceiling;
   - second call, after the server's window: no deposit, a voucher only; the server's cumulative had moved to 1,006,412, so the wallet took the corrective 402,
     verified the server's last voucher against its own key and the chain, resynced and retried once; the result was read.
   - the server clamps a per-run ceiling below 1.00 up to 1.00; agpay's `--deposit-multiplier 3` keeps the deposit at the minimum the server asks for.

## Found by live use

- The per-payment limit must not apply to a channel deposit: a 3.00 deposit was refused under the default policy until deposits got their own cap (`max_deposit`).
- Polygon gas spikes (275 gwei) need a fee cap with headroom and a longer receipt wait; Base needs a margin for the L1 data fee in `send --native --all`.

## Not tested live

Solana batch-settlement (not implemented), the escrow `deal create` with real money (the message format is tested against the server's own code), Arbitrum, Optimism and Ethereum (opt-in networks).
