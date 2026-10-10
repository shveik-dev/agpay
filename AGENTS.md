# AGENTS.md (agpay)

Go wallet CLI for AI agents: `cmd/agpay` + `internal/{secp,evm,sol,chain,vault,policy,x402pay,app}`. Read `README.md` then `SECURITY.md`.

- Everything runs in rootless podman: `./build.sh` (vet, tests, static build). Tests are offline; `testdata/golden.json` holds values produced by
  the agdata server code (regenerate from the agdata repo, never by hand).
- Dependencies stay at the standard library plus `golang.org/x/crypto`. Do not add a third-party module.
- Every command prints one JSON document; keep the exit codes and error codes in `internal/app/describe.go` in step with the code.
- Money safety first: a spend is reserved in the ledger before it is signed; policy checks happen before signatures; never weaken a guard
  without the owner. Live tests use a funded test wallet and small amounts; pass the key to the container as an environment variable, never on a command line.
- Nothing is published without the owner's approval.
