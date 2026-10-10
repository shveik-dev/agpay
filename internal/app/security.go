package app

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"os"
	"syscall"

	"github.com/shveik-dev/agpay/internal/chain"
	"github.com/shveik-dev/agpay/internal/policy"
	"github.com/shveik-dev/agpay/internal/vault"
)

// checkPrivate refuses a secret-bearing file that another user could read or replace: it must be
// a regular file (not a symlink) owned by the current user with no group or other permissions.
func checkPrivate(path, what string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return walletErr("unsafe_file", "use a regular file, not a symlink or device", "%s %s is not a regular file", what, path)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return walletErr("unsafe_file", fmt.Sprintf("chmod 600 %s", path), "%s %s is readable or writable by other users (mode %s)", what, path, fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return walletErr("unsafe_file", "", "%s %s belongs to another user", what, path)
	}
	return nil
}

// checkHome makes sure the data directory is private to this user.
func checkHome(home string) error {
	fi, err := os.Lstat(home)
	if err != nil {
		return nil // not created yet
	}
	if !fi.IsDir() {
		return walletErr("unsafe_file", "", "%s is not a directory", home)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return walletErr("unsafe_file", fmt.Sprintf("chmod 700 %s", home), "the data directory %s is writable by other users", home)
	}
	return nil
}

func ledgerKey(v *vault.Vault) []byte {
	k, _ := hkdf.Key(sha256.New, v.Secrets.EVMPriv(), nil, "agpay/ledger/v1", 32)
	return k
}

// extras reads the owner-added networks out of the policy file without verifying it: only for
// read-only display commands. Anything that signs goes through client(), which verifies.
func (c *ctx) registryUnverified() *chain.Registry {
	if b, err := os.ReadFile(c.path("policy.json")); err == nil {
		var s policy.Signed
		if jsonUnmarshal(b, &s) == nil {
			if r, err := chain.WithExtra(s.Rules.Extra); err == nil {
				return r
			}
		}
	}
	return chain.Builtin()
}
