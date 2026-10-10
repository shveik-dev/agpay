// Package vault keeps the wallet's keys encrypted at rest: scrypt (N=2^17) stretches a passphrase
// into a key for XChaCha20-Poly1305. The file carries only the public addresses in clear.
package vault

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"

	"github.com/shveik-dev/agpay/internal/evm"
	"github.com/shveik-dev/agpay/internal/secp"
	"github.com/shveik-dev/agpay/internal/sol"
)

const (
	scryptN = 1 << 17
	scryptR = 8
	scryptP = 1
)

// Secrets is what the encrypted blob holds.
type Secrets struct {
	Seed      string `json:"seed,omitempty"`       // hex, 32 bytes; both keys derive from it
	EVMKey    string `json:"evm_key"`              // hex, 32 bytes
	SolSeed   string `json:"sol_seed"`             // hex, 32 bytes (ed25519 seed)
	Admin     string `json:"admin,omitempty"`      // hex ed25519 public key that signs the spending policy
	PolicySeq int64  `json:"policy_seq,omitempty"` // lowest policy sequence number still accepted (blocks rollback)
}

type file struct {
	Version int    `json:"version"`
	EVM     string `json:"evm_address"`
	Solana  string `json:"solana_address"`
	KDF     struct {
		Name string `json:"name"`
		N    int    `json:"n"`
		R    int    `json:"r"`
		P    int    `json:"p"`
		Salt string `json:"salt"`
	} `json:"kdf"`
	Cipher string `json:"cipher"`
	Nonce  string `json:"nonce"`
	Data   string `json:"ciphertext"`
}

type Vault struct {
	Path    string
	EVM     evm.Address
	Solana  sol.Address
	Secrets Secrets
}

func (s *Secrets) EVMPriv() []byte { b, _ := hex.DecodeString(s.EVMKey); return b }
func (s *Secrets) SolKey() ed25519.PrivateKey {
	b, _ := hex.DecodeString(s.SolSeed)
	return sol.KeyFromSeed(b)
}

// Derive builds both keys from one 32-byte seed with HKDF-SHA256 (domain separated).
func Derive(seed []byte) (Secrets, error) {
	e, err := hkdf.Key(sha256.New, seed, nil, "agpay/evm/v1", 32)
	if err != nil {
		return Secrets{}, err
	}
	for i := 0; ; i++ { // a rejected scalar is astronomically rare; re-derive with a counter
		if _, err := secp.PublicKey(e); err == nil {
			break
		}
		e, _ = hkdf.Key(sha256.New, seed, nil, fmt.Sprintf("agpay/evm/v1/%d", i), 32)
	}
	s, err := hkdf.Key(sha256.New, seed, nil, "agpay/solana/v1", 32)
	if err != nil {
		return Secrets{}, err
	}
	return Secrets{Seed: hex.EncodeToString(seed), EVMKey: hex.EncodeToString(e), SolSeed: hex.EncodeToString(s)}, nil
}

func NewSeed() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	return b, err
}

func (s *Secrets) addresses() (evm.Address, sol.Address, error) {
	ea, err := evm.AddressOf(s.EVMPriv())
	if err != nil {
		return evm.Address{}, sol.Address{}, fmt.Errorf("evm key: %w", err)
	}
	sb, err := hex.DecodeString(s.SolSeed)
	if err != nil || len(sb) != 32 {
		return evm.Address{}, sol.Address{}, errors.New("solana seed must be 32 bytes of hex")
	}
	return ea, sol.AddressOf(sol.KeyFromSeed(sb)), nil
}

// Create writes a new vault; it refuses to overwrite one.
func Create(path string, s Secrets, passphrase string) (*Vault, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("a wallet already exists at %s", path)
	}
	v := &Vault{Path: path, Secrets: s}
	var err error
	if v.EVM, v.Solana, err = s.addresses(); err != nil {
		return nil, err
	}
	return v, v.Save(passphrase)
}

// Save encrypts the secrets under the passphrase and replaces the file atomically (0600).
func (v *Vault) Save(passphrase string) error {
	if len(passphrase) < 12 {
		return errors.New("passphrase must be at least 12 characters")
	}
	var f file
	f.Version = 1
	f.EVM, f.Solana = v.EVM.Hex(), v.Solana.String()
	salt := make([]byte, 16)
	rand.Read(salt)
	f.KDF.Name, f.KDF.N, f.KDF.R, f.KDF.P, f.KDF.Salt = "scrypt", scryptN, scryptR, scryptP, base64.StdEncoding.EncodeToString(salt)
	key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	plain, _ := json.Marshal(v.Secrets)
	f.Cipher = "xchacha20poly1305"
	f.Nonce = base64.StdEncoding.EncodeToString(nonce)
	f.Data = base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plain, []byte(f.EVM+f.Solana)))
	out, _ := json.MarshalIndent(f, "", "  ")
	if err := os.MkdirAll(filepath.Dir(v.Path), 0o700); err != nil {
		return err
	}
	tmp := v.Path + ".tmp"
	if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.Path)
}

// Public reads the addresses without a passphrase.
func Public(path string) (evm.Address, sol.Address, error) {
	var f file
	b, err := os.ReadFile(path)
	if err != nil {
		return evm.Address{}, sol.Address{}, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return evm.Address{}, sol.Address{}, err
	}
	ea, err := evm.ParseAddress(f.EVM)
	if err != nil {
		return ea, sol.Address{}, err
	}
	sa, err := sol.ParseAddress(f.Solana)
	return ea, sa, err
}

var ErrWrongPassphrase = errors.New("wrong passphrase, or the wallet file was changed")

func Open(path, passphrase string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f file
	if err := json.Unmarshal(b, &f); err != nil || f.Version != 1 || f.KDF.Name != "scrypt" || f.Cipher != "xchacha20poly1305" {
		return nil, errors.New("not a wallet file this version understands")
	}
	if f.KDF.N < 1<<14 || f.KDF.N > 1<<20 || f.KDF.R != 8 || f.KDF.P < 1 || f.KDF.P > 4 {
		return nil, errors.New("wallet file has unreasonable scrypt parameters")
	}
	salt, err1 := base64.StdEncoding.DecodeString(f.KDF.Salt)
	nonce, err2 := base64.StdEncoding.DecodeString(f.Nonce)
	ct, err3 := base64.StdEncoding.DecodeString(f.Data)
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("wallet file is corrupt")
	}
	key, err := scrypt.Key([]byte(passphrase), salt, f.KDF.N, f.KDF.R, f.KDF.P, 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, nonce, ct, []byte(f.EVM+f.Solana))
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	v := &Vault{Path: path}
	if err := json.Unmarshal(plain, &v.Secrets); err != nil {
		return nil, errors.New("wallet contents are corrupt")
	}
	if v.EVM, v.Solana, err = v.Secrets.addresses(); err != nil {
		return nil, err
	}
	if v.EVM.Hex() != f.EVM || v.Solana.String() != f.Solana {
		return nil, errors.New("wallet addresses do not match its keys")
	}
	return v, nil
}

// ParseSolanaSecret accepts the formats Solana tools export: a base58 64-byte keypair (seed||public),
// a base58 32-byte seed, or a 32-byte hex seed. It returns the hex seed.
func ParseSolanaSecret(s string) (string, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(strings.TrimPrefix(s, "0x")); err == nil && len(b) == 32 {
		return hex.EncodeToString(b), nil
	}
	b, err := sol.B58Decode(s)
	if err != nil {
		return "", errors.New("not a Solana secret key (base58 keypair or seed, or 32-byte hex)")
	}
	switch len(b) {
	case 32:
		return hex.EncodeToString(b), nil
	case 64:
		if !bytes.Equal(ed25519.NewKeyFromSeed(b[:32]), b) {
			return "", errors.New("the 64-byte Solana key is inconsistent (seed does not match its public half)")
		}
		return hex.EncodeToString(b[:32]), nil
	}
	return "", errors.New("a Solana secret key is 32 or 64 bytes")
}

// ParseEVMKey normalises a hex private key (with or without 0x) and checks it is valid.
func ParseEVMKey(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", errors.New("an EVM private key is 32 bytes of hex")
	}
	if _, err := secp.PublicKey(b); err != nil {
		return "", err
	}
	return strings.ToLower(s), nil
}
