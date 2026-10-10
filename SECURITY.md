# Security model

## What this protects, and against whom

agpay is built for an agent that can be wrong or be talked into things (prompt injection through a web page, a hostile API,
a confused plan) and that runs commands as one operating-system user. It limits what such an agent can spend and what it can
change. It is not a defence against an attacker who already runs code as the same user with the wallet passphrase: that
attacker can do what the agent can, and, with write access to the home directory, more. For that, run agpay as its own user,
keep the passphrase in a secret mount only that user reads, and keep the admin passphrase somewhere else entirely.

## Keys
- One 32-byte random seed -> HKDF-SHA256 with distinct labels -> an EVM key and a Solana key. Imported keys are supported.
- At rest: `wallet.json`, scrypt N=2^17 r=8 p=1 (about 128 MB, 0.3 s) then XChaCha20-Poly1305; the addresses are authenticated data.
  The file is rewritten atomically with mode 600; the passphrase needs at least 12 characters (generated ones are 256 bits).
- In memory only while a command runs. The process sets `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` (no core, no ptrace or `/proc/PID/mem`
  from other processes). Go cannot promise to wipe string copies of key material; the process is short lived on purpose.
- secp256k1 is implemented on `math/big` (deterministic RFC 6979 nonces, low-s) and is not constant time. This is a local process
  whose timing nobody observes; do not expose it as a network signing service.

## Secrets in, secrets out
- Passphrases are read from a file (`AGPAY_PASSPHRASE_FILE`, `AGPAY_ADMIN_PASSPHRASE_FILE`, `--passphrase-file`) or the environment, never
  from argv. A file must be a regular file, not a symlink, owned by you, mode 600; the data directory must not be writable by others.
  An environment passphrase is removed from the process environment after it is read.
- No command prints a key except `export`, which needs `--i-understand` and the admin passphrase.
- Errors never contain secrets. Output is JSON-encoded, so a hostile response body cannot inject terminal escapes.

## Spending rules (enforced before any signature)
- Per payment, per rolling 24 h (all networks), per channel deposit, allowed hosts (wildcards ok), networks, schemes; https only
  (loopback excepted); a per-call `--max`. Limits and the daily total are checked and recorded under one file lock, so parallel
  processes cannot both pass.
- Only each network's registered USDC is paid (contract/mint compared to the built-in or admin-added registry); the EIP-712 domain
  chain id and contract come from that registry, not from the server. `payTo` must be a usable, non-zero address.
- EIP-3009 authorizations are valid for at most 10 minutes (deposits 15) whatever `maxTimeoutSeconds` says, so a signature a server
  keeps cannot be redeemed next month. The daily budget counts a signed but unconfirmed authorization until it expires.
- Redirects are never followed; the paid request goes to the URL that was quoted.
- Batch channels: deposit size is clamped to the policy; `chargedAmount` from a server is untrusted and capped at the quoted
  amount; the server's channel state is adopted only after its voucher verifies against the wallet's own signer and the chain.
- `--idempotency-key` makes a retry after a timeout refuse to pay twice.

## The policy and who can change it
- `agpay init --generate-admin-passphrase-file F` derives an Ed25519 admin key from a second passphrase (scrypt). The wallet stores only
  the public key; `policy.json` is signed with the private key. Without the signature, or with another wallet's policy, or an older
  one (sequence numbers only move forward), every payment is refused (`policy_invalid`): fail closed, never fall back to looser rules.
- `policy set`, `export` and `rotate-passphrase` require the admin passphrase. Added networks and their RPC endpoints live in the
  signed policy; there is no unsigned network file.
- If you skip the admin passphrase at init, the policy is an ordinary file and anyone who can write it can change it.

## Ledger
`spend.jsonl` lines carry an HMAC (key derived from the wallet key) chained to the previous line. Editing, reordering or dropping a
line breaks the chain; spending then stops with `ledger_tampered`/`ErrTampered` until the owner looks. Deleting the whole file
resets the daily total: it is not detectable without an external witness. Run the wallet as its own user if that matters.

## Signing other things
`sign-message` signs EIP-191 personal messages (the `\x19Ethereum Signed Message` prefix cannot start a transaction) and, on Solana,
only inside the off-chain message envelope (`\xffsolana offchain` header): raw Ed25519 over caller bytes could be a transaction.

## Known limits
- Solana `batch-settlement` is not implemented (offers are refused, not mis-signed).
- A malicious RPC endpoint can lie about balances; that can make a payment fail or a check pass wrongly, but a signature only ever
  covers the quoted amount, token and receiver, and settlement is verified by the facilitator on chain.
- The server decides what the `exact` payment buys. A paid but empty response is the server's to refund; `payment_unconfirmed`
  means the response was lost after signing.
