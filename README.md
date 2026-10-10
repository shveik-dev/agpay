# agpay

A wallet for AI agents: it holds USDC, pays x402 APIs, and stays inside spending limits its owner signed.

agpay is one static Go binary that depends only on the Go standard library and `golang.org/x/crypto`. It holds USDC on
Base, Polygon and Solana, pays any [x402](https://github.com/x402-foundation/x402) endpoint (single `exact` payments, or
[batch-settlement](https://github.com/x402-foundation/x402/tree/main/specs/schemes/batch-settlement) channels on EVM),
drives the [agpay.shveik.dev](https://agpay.shveik.dev) escrow between two agents, and serves the same wallet as an MCP
server on stdio.

It is built to be driven by an agent: every command prints exactly one JSON document, every failure has a stable error
code and exit code, and nothing ever prompts.

- **Limits the owner signs.** Per payment, per rolling day and per channel deposit (defaults $1, $10, $5), plus allowed
  hosts, networks and schemes, all checked before anything is signed. The policy is signed with an admin passphrase that
  the agent does not hold.
- **USDC only, to the quoted receiver.** A server cannot choose the token, authorizations expire within 10 minutes, and
  a payment is never sent on through a redirect.
- **An interface for agents.** `--dry-run`, `--idempotency-key`, a per-call `--max`, response bodies marked untrusted,
  and `agpay describe` for the whole interface as JSON.
- **Paid live.** `exact` on Base, Polygon and Solana mainnet; `batch-settlement` on Base mainnet against a production
  server.
- **Small and checkable.** secp256k1, base58, Solana transaction encoding and the x402 client are written here and
  tested against go-ethereum's output and the server-side implementation.

## Quickstart

You need podman, a Go module cache that already holds `golang.org/x/crypto` (the build runs offline; see
[Build and test](#build-and-test)), and some USDC on Base, Polygon or Solana.

```sh
./build.sh                          # tests, then a static binary in ./dist/agpay
cp dist/agpay ~/.local/bin/         # or anywhere on your PATH

# The agent keeps the wallet passphrase. You keep the admin passphrase.
agpay init --generate-passphrase-file "$HOME/.agpay.pass" \
           --generate-admin-passphrase-file ./owner-admin.pass
export AGPAY_PASSPHRASE_FILE="$HOME/.agpay.pass"

agpay address    # send USDC to these addresses; no gas token is needed to pay
agpay doctor     # checks the passphrase, policy, wallet file and RPC endpoints
agpay pay https://agdata.shveik.dev/x402/web-search --data '{"query":"x402"}' --max 0.05
```

Then move `owner-admin.pass` off the agent's machine. With only the wallet passphrase, an agent can pay within the
limits, but it cannot raise them, export keys or rotate the passphrase. If you skip `--generate-admin-passphrase-file`,
the policy is an unsigned file that anything able to write it can change.

## Example: one paid call, start to finish

```sh
agpay balance --network base                                   # is there money?
agpay quote https://api.example.com/x402/search --data '{"query":"x"}'
agpay pay   https://api.example.com/x402/search --data '{"query":"x"}' \
            --max 0.05 --idempotency-key task-42-search
agpay history                                                  # what was spent, against today's limit
```

`quote` signs nothing. It lists every offer in the 402 and says whether the policy allows it (output trimmed):

```json
{"command":"quote","ok":true,"result":{"offers":[
  {"scheme":"exact","network":"eip155:8453","amount_atomic":"10000","amount_usdc":"0.01","pay_to":"0x…","allowed":true},
  {"scheme":"batch-settlement","network":"solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp","amount_atomic":"10000",
   "amount_usdc":"0.01","pay_to":"…","allowed":false,"reason":"batch-settlement is only implemented on EVM networks"}],
  "payable":true,"payment_required":true,"status":402,"x402_version":2}}
```

`pay` returns the response together with the receipt. The body is third-party data and is marked so (output trimmed):

```json
{"command":"pay","ok":true,"result":{
  "body":{"results":["…"]},"body_is_untrusted":true,"bytes":2048,"content_type":"application/json","paid":true,
  "payment":{"amount_atomic":"10000","amount_usdc":"0.01","network":"eip155:8453","pay_to":"0x…","scheme":"exact",
             "settlement":{"success":true,"transaction":"0x…","network":"eip155:8453","payer":"0x…"},
             "spend_id":"3f9c0a7e5b1d2c48"},
  "status":200}}
```

A refusal is a JSON document too, with a stable code and exit status. Here the price is above this call's `--max`:

```json
{"command":"pay","detail":{"offers":[…]},"error":{"code":"no_acceptable_offer",
 "message":"none of the server's offers can be paid under the policy",
 "hint":"run `agpay quote` to see why each offer was refused","retryable":false,"exit_code":3},"ok":false}
```

Running `pay` again with the same `--idempotency-key` returns `already_paid` (exit 4) instead of paying twice.
`history` lists each spend (host, network, scheme, amount, status, transaction) and the total counted against the daily
limit.

## Commands

| Command | What it does |
|---|---|
| `init` | Create the wallet: one random seed gives an EVM key and a Solana key, encrypted at rest. Import existing keys with `--evm-key-env` and `--solana-key-env`. |
| `address` | Print the EVM and Solana addresses. Needs no passphrase. |
| `balance` | USDC and gas-token balances per network (`--network`, `--testnets`). |
| `networks` | The networks and USDC contracts the wallet will pay in. |
| `quote URL` | What a URL costs and which offers the policy allows. Signs nothing. |
| `pay URL` (alias `fetch`) | Call a paid URL, pay its 402 within the policy, and return the response. |
| `channels list` / `channels refund URL` | List open batch-settlement channels; ask a server for a cooperative refund (`--amount`, default all). |
| `history` | Spends over the last `--hours` (default 24) and the total counted against the daily limit. |
| `policy show` / `policy set` | Show or change the limits. `set` needs the admin passphrase. |
| `send` | Send USDC (or the gas token with `--native`) to an address on the policy's `allow_send_to` list. Off until the owner adds one. |
| `sign-message` | Sign text as EIP-191 (`--chain evm`) or as a Solana off-chain message. It cannot sign a transaction. |
| `deal ...` | The agpay.shveik.dev escrow, buyer and seller sides (see [Escrow between agents](#escrow-between-agents)). |
| `export --i-understand` | Print the secret keys for backup or migration. Needs the admin passphrase. |
| `rotate-passphrase` | Re-encrypt the wallet under a new passphrase. Needs the admin passphrase. |
| `doctor` | Check the wallet, passphrase, policy, file modes and RPC reachability, with a fix for each problem. |
| `describe` | Every command, flag, error code and exit code as JSON, including which commands move money. |
| `mcp` | Serve the wallet as an MCP server on stdio. |

"Needs the admin passphrase" applies when one was set at `init`.

**`pay` flags:** `--max USD` (this call's ceiling), `--dry-run`, `--idempotency-key K` (a retry never pays twice),
`--network`, `--scheme exact|batch-settlement`, `--deposit-multiplier N`, `-X METHOD`, `-H "Name: value"`,
`--data BODY` (or `@file`, `@-` for stdin), `--out FILE` (bodies over 1 MiB are truncated without it), `--timeout`.

**Which offer is paid:** of the offers the policy allows, `pay` prefers an open channel with room, then `exact`
(Base before other networks), then opening a new channel. Ties go to the cheaper offer. `--network` and `--scheme`
narrow the choice.

**Policy flags** (`policy set`): `--max-payment`, `--max-day`, `--max-deposit` (dollars), `--hosts` (wildcards such as
`*.example.com`), `--networks`, `--schemes`, `--allow-http`, `--send-to`, `--add-network-file`, `--clear-networks`.

### Output, exit codes and environment

Every command prints one JSON object on stdout: `{"ok":true,"command":...,"result":...}` or
`{"ok":false,"command":...,"error":{"code","message","hint","retryable","exit_code"}}`, sometimes with a `detail` that
holds the quote or partial receipt. `--pretty` indents it. (`mcp` speaks JSON-RPC instead.)

| Exit | Meaning |
|---|---|
| `0` | ok |
| `1` | unexpected error |
| `2` | usage: bad command or flags |
| `3` | refused by the spending policy |
| `4` | payment failed or was rejected |
| `5` | insufficient funds |
| `6` | wallet missing or passphrase wrong |
| `7` | network error (check `retryable`) |

| Variable | Purpose |
|---|---|
| `AGPAY_HOME` | Data directory (or `--home DIR`; default `~/.agpay`) |
| `AGPAY_PASSPHRASE_FILE` | File holding the wallet passphrase (preferred) |
| `AGPAY_PASSPHRASE` | The passphrase itself (less safe: visible in the process environment) |
| `AGPAY_ADMIN_PASSPHRASE_FILE` | File holding the admin passphrase, for policy changes |
| `AGPAY_SERVICE_URL` | Escrow origin (default `https://agpay.shveik.dev`) |

The data directory holds `wallet.json` (encrypted keys), `policy.json` (signed limits), `spend.jsonl` (the ledger),
`channels.json` and `deals.json`, all mode 600.

### MCP server

`agpay mcp` serves the wallet over stdio (newline-delimited JSON-RPC 2.0, MCP protocol `2024-11-05`) with six tools:
`wallet_address`, `wallet_balance`, `quote`, `pay`, `payment_history` and `spending_policy`. Each tool runs the
matching command in-process, so the same policy, ledger and error codes apply. No tool changes the policy, sends funds
out or exports keys.

```json
{
  "mcpServers": {
    "agpay": {
      "command": "agpay",
      "args": ["mcp"],
      "env": { "AGPAY_PASSPHRASE_FILE": "/home/agent/.agpay.pass" }
    }
  }
}
```

Use `AGPAY_PASSPHRASE_FILE` here. A passphrase given in `AGPAY_PASSPHRASE` is removed from the process environment
after its first read, so later tool calls in the same server would not find it.

## Batch-settlement channels (EVM)

With `exact`, every call is its own on-chain transfer. With `batch-settlement`, the wallet funds a channel once and pays
each call with a signed voucher. The server claims vouchers on chain later, in batches.

1. **Open.** The server's 402 offers `batch-settlement` with a `receiverAuthorizer` and a `withdrawDelay` (15 minutes to
   30 days). The wallet derives the channel id from payer, receiver, authorizers, token and delay, then signs a deposit:
   an ERC-3009 `receiveWithAuthorization` to the canonical deposit collector, with its nonce bound to the channel id,
   valid for at most 15 minutes, plus the first voucher.
2. **Size the deposit.** The server's `minDeposit` when it sends a valid one, otherwise 5 times the call price
   (`--deposit-multiplier N`, N of 3 or more). It is never more than the policy's `max_deposit` ($5 by default).
3. **Pay.** Each later call signs a cumulative voucher: everything charged so far plus this call's price as a ceiling.
   No transaction is sent per call. The server reports what it actually charged (`chargedAmount`), and the wallet caps
   that at the quoted price. When the balance runs out, the next channel payment tops it up with a new deposit.
4. **Recover.** On a corrective 402 (`cumulative_amount_mismatch`, `cumulative_below_claimed`), the wallet reads the
   channel on chain. It adopts the server's state only if the voucher the server holds verifies against the wallet's
   own key and the server's charged amount lies between what the chain shows as claimed and that voucher's ceiling.
   Then it retries once.
5. **Close.** `channels refund URL` asks the server for a cooperative refund of the unspent balance, signed as a
   zero-charge voucher.

```sh
# the first call opens the channel: one deposit plus a voucher
agpay pay https://api.example.com/x402/run --data @job.json --scheme batch-settlement --max 0.10
# later calls that land on the same channel reuse it while it has room: one voucher, no transaction
agpay pay https://api.example.com/x402/run --data @job2.json --max 0.10
agpay channels list                                        # balance, charged so far, last signed voucher
agpay channels refund https://api.example.com/x402/run     # take back what is left
```

The receipt of a channel payment adds `channel_id` and, when a deposit was signed, `deposit_atomic`. Contracts:
x402BatchSettlement `0x4020074e9dF2ce1deE5A9C1b5c3f541D02a10003`, ERC-3009 deposit collector
`0x4020806089470a89826cB9fB1f4059150b550004`.

**How it was verified**

- **Against a production server.** On Base mainnet, agpay paid agi.apify.com through a channel end to end: an ERC-3009
  deposit opened it, cumulative vouchers paid the calls, the server returned a settlement receipt, and the paid result
  was read back.
- **On chain, by hand.** `AGPAY_LIVE_KEY=<funded key> go test ./internal/x402pay -run Live -v` plays both sides on Base
  mainnet: a real deposit through the canonical contract, a voucher the contract accepts in a real `claim`, then a
  cooperative `refund`. The channel ends holding exactly the claimed amount. This sends real transactions.
- **Simulated against the canonical contract.** `AGPAY_ONCHAIN_TEST_KEY=<funded key> go test ./internal/x402pay -run Real -v`
  checks with `eth_call` that the contract accepts the deposit the wallet signs and refuses a copy with a broken nonce
  binding. Nothing is sent.
- **Offline.** The channel id, voucher and `ReceiveWithAuthorization` digests equal go-ethereum's EIP-712 output. The
  EIP-3009 digest, secp256k1 signatures, Solana ATAs and v0 messages equal the agdata.shveik.dev server's code, byte
  for byte.

## Escrow between agents

`agpay deal` drives [agpay.shveik.dev](https://agpay.shveik.dev), a custodial hold between a buyer agent and a seller
agent, with this wallet's keys.

```sh
# buyer
agpay deal create --seller 0xSELLER --amount 5.00 --ref job-17   # pays the hold with x402
agpay deal status dl_...
agpay deal confirm dl_...                                        # release to the seller
agpay deal dispute dl_... --reason "not delivered"

# seller (the wallet whose address is the deal's seller)
agpay deal accept dl_...
agpay deal deliver dl_...
```

- Buyer: `create`, `status`, `confirm`, `dispute --reason`, `statement --text`, `list`. Seller: `accept`, `deliver`,
  `refund`, `statement --as seller`, `list --as seller`.
- `create` takes whole cents from 0.50 to 500.00 and optional `--deadline-hours` (1 to 720, default 168),
  `--review-hours` (48 to 336, default 168), `--instant`, `--network` (default `base`), `--max` and
  `--idempotency-key`.
- The hold is an ordinary x402 payment, so the policy applies: a deal above $1 needs a higher `max_payment`.
- The buyer's secret is generated locally and written to `deals.json` before any money moves. It is sent only as the
  bearer token of the buyer's own follow-up calls. Seller actions are EIP-191 signatures over the host, deal, action,
  amount and expiry.

## Security model

A summary. The full version is in [SECURITY.md](SECURITY.md).

- **Threat model.** An agent that can be wrong or be talked into things (prompt injection, a hostile API), running as
  one operating-system user. agpay limits what that agent can spend and change. It does not defend against an attacker
  who already runs code as the same user with the wallet passphrase; for that, run agpay as its own user.
- **Keys.** One random 32-byte seed derives an EVM key and a Solana key (HKDF-SHA256). At rest they are encrypted with
  scrypt (N=2^17) and XChaCha20-Poly1305. Passphrases come from files (regular, owned by you, mode 600) or the
  environment, never from argv.
- **Limits before signatures.** Per payment, per rolling day, per channel deposit, hosts, networks and schemes; https
  only (loopback excepted). Limits are checked and the spend is recorded under one file lock, so parallel processes
  cannot both pass.
- **Only USDC.** Only each network's registered USDC is paid, and the EIP-712 domain comes from the built-in registry,
  not from the server. Authorizations are valid for at most 10 minutes (deposits 15), whatever the server asks.
- **Signed policy.** The policy is signed by an Ed25519 admin key derived from a second passphrase, bound to this
  wallet, and protected against rollback. A missing or invalid signature, another wallet's policy, or an older one
  stops every payment (`policy_invalid`). `policy set`, `export` and `rotate-passphrase` need the admin passphrase.
- **Tamper-evident ledger.** `spend.jsonl` is HMAC-chained. An edited, reordered or dropped line stops spending
  (`ledger_tampered`).
- **Untrusted responses.** Response bodies carry `"body_is_untrusted": true`; an agent must not follow instructions in
  them. Output is JSON-encoded, so a body cannot inject terminal escapes.
- **Other guards.** Redirects are never followed with a payment attached. On Linux the process disables core dumps
  and ptrace. `sign-message` signs only inside EIP-191 or the Solana off-chain envelope, so it can never sign a
  transaction.

## Spec compatibility

| Spec | Status |
|---|---|
| x402 v2 transport (`PAYMENT-REQUIRED` / `PAYMENT-SIGNATURE` / `PAYMENT-RESPONSE`) | Yes. v1 (`X-PAYMENT`, 402 body) too. |
| `exact` on EVM, EIP-3009 `transferWithAuthorization` | Yes. Paid live on Base and Polygon mainnet. Arbitrum, Optimism and Ethereum run the same code but are opt-in, because no live payment has been made on them yet. |
| `exact` on Solana (`TransferChecked` + memo, Token and Token-2022) | Yes. Paid live on Solana mainnet. |
| `batch-settlement` on EVM (ERC-3009 `receiveWithAuthorization` deposit, cumulative vouchers, corrective 402 recovery, cooperative refund) | Yes. Run live on Base mainnet against agi.apify.com. |
| `batch-settlement` on Solana (payment-channels program) | No. The offer is refused with a reason. |
| `exact` with Permit2 or ERC-7710 | No. Only each network's USDC is paid, and USDC supports EIP-3009. |
| MCP over stdio (protocol `2024-11-05`, tools) | Yes. |

To add an opt-in network, the owner signs it into the policy: `agpay policy set --add-network-file nets.json`, where the
file is a JSON array of `{caip, kind, usdc, rpc[, name, v1, chain_id, decimals]}`.

## Build and test

Everything runs in rootless podman (`golang:1.25`):

```sh
./build.sh                  # go vet, every test, then a static linux/amd64 binary in ./dist/agpay
VERSION=v0.1.0 ./build.sh   # the same, with the version that `agpay describe` reports
```

The containers have no network (`--network=none`, `GOPROXY=off`), a read-only source mount and a build cache in RAM.
Modules come from your Go module cache, mounted read-only (`GOMODCACHE_HOST`, default `~/go/pkg/mod`), so it must
already hold `golang.org/x/crypto`; one `go mod download` fills it.

The tests are offline. `testdata/golden.json` holds reference values produced by the agdata.shveik.dev server code;
regenerate it from there, never by hand. The live tests above are opt-in and need network access and a funded key.

Dependencies: the Go standard library and `golang.org/x/crypto` (sha3, scrypt, chacha20poly1305; maintained by the Go
team) plus its `golang.org/x/sys/cpu`.

## Limits

- **Solana `batch-settlement` is not implemented.** Such offers are refused with a reason, never signed wrongly.
- **USDC only.** No other token, and no `exact` payments through Permit2 or ERC-7710.
- **Built-in networks are Base, Polygon and Solana** (plus Base Sepolia and Solana Devnet). Other EVM networks are
  opt-in through the signed policy, and no live payment has been made on them yet.
- **No unilateral channel exit.** agpay does not implement the contract's timed withdrawal (`initiateWithdraw` /
  `finalizeWithdraw`). If a server stops cooperating, getting the unspent deposit back means calling the contract
  directly with the exported key. Keep `max_deposit` small.
- **Channel spending is over-counted.** The daily total counts the whole deposit when it is signed and each later
  voucher again, so it can reach the daily limit before the money is actually spent.
- **Deleting the whole ledger resets the daily total.** An external witness is needed to detect that. If it matters,
  run the wallet as its own user.
- **RPC endpoints are trusted for reads.** A malicious RPC can lie about balances. That can make a payment fail or a
  check pass wrongly, but a signature only ever covers the quoted amount, token and receiver.
- **The server decides what an `exact` payment buys.** A paid but empty response is the server's to refund.
  `payment_unconfirmed` means the response was lost after signing: check `agpay history` before paying again.
- **The escrow is custodial.** agpay.shveik.dev holds the funds between `create` and release.
- **Local signing only.** secp256k1 is implemented on `math/big` and is not constant time. Do not expose agpay as a
  network signing service. Go cannot promise to wipe copies of key material from memory; the process is short-lived on
  purpose, and the core-dump and ptrace protection applies on Linux only.
- **Linux first.** `build.sh` produces a linux/amd64 binary.
