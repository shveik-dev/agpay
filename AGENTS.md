# AGENTS.md (agpay)

Go wallet CLI for AI agents: `cmd/agpay` and `internal/{secp,evm,sol,chain,vault,policy,x402pay,app}`. Read `README.md`, then `SECURITY.md`.

- Build and test in rootless podman: `./build.sh` (vet, tests, static build). Tests are offline. `testdata/golden.json` and `testdata/agpsig.json` hold values produced
  by independent reference implementations (a secp256k1/EIP-712 library, a Solana transaction encoder, the escrow service's message code); regenerate them from those, never by hand.
- Dependencies stay at the standard library plus `golang.org/x/crypto`. Do not add a third-party module.
- Every command prints one JSON document. Keep the exit codes and error codes in `internal/app/describe.go` in step with the code.
- Money safety first: a spend is reserved in the ledger before it is signed; policy checks run before any signature; never weaken a guard without the owner's say.
- Live tests (`AGPAY_ONCHAIN_TEST_KEY`, `AGPAY_LIVE_KEY`) use a funded test wallet and small amounts; pass the key to the container as an environment variable, never on a command line, and never print it.
- Never run `agpay export` in an automated session: it prints private keys.
- Public repo: never commit secret-store names, sensitive environment variable names, owner wallet addresses, internal hostnames or work emails, even without values. Check the whole history before any push.
- Live test history and what each run taught us: `docs/live-tests.md`.
