// Package secp implements secp256k1 ECDSA signing with public key recovery on math/big, so the
// wallet needs no third-party curve library. Signatures are deterministic (RFC 6979) and low-s.
// math/big is not constant time; the wallet is a local process whose timing nobody can observe
// over a network, and the nonce is deterministic, so this is an accepted limit (see README).
package secp

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"math/big"
)

var (
	P, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	N, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	halfN = new(big.Int).Rsh(N, 1)
	b7    = big.NewInt(7)
)

type point struct{ x, y, z *big.Int } // Jacobian; z == 0 is infinity

func inf() point            { return point{new(big.Int), new(big.Int), new(big.Int)} }
func (p point) isInf() bool { return p.z.Sign() == 0 }

func mod(a *big.Int) *big.Int { a.Mod(a, P); return a }

func double(p point) point {
	if p.isInf() || p.y.Sign() == 0 {
		return inf()
	}
	ysq := mod(new(big.Int).Mul(p.y, p.y))
	s := mod(new(big.Int).Mul(p.x, ysq))
	s.Lsh(s, 2)
	mod(s)
	m := mod(new(big.Int).Mul(p.x, p.x))
	m.Mul(m, big.NewInt(3))
	mod(m)
	x := mod(new(big.Int).Mul(m, m))
	x.Sub(x, new(big.Int).Lsh(s, 1))
	mod(x)
	y := new(big.Int).Sub(s, x)
	y.Mul(y, m)
	y.Sub(y, new(big.Int).Lsh(mod(new(big.Int).Mul(ysq, ysq)), 3))
	mod(y)
	z := mod(new(big.Int).Mul(p.y, p.z))
	z.Lsh(z, 1)
	mod(z)
	return point{x, y, z}
}

func add(p, q point) point {
	if p.isInf() {
		return q
	}
	if q.isInf() {
		return p
	}
	z1z1 := mod(new(big.Int).Mul(p.z, p.z))
	z2z2 := mod(new(big.Int).Mul(q.z, q.z))
	u1 := mod(new(big.Int).Mul(p.x, z2z2))
	u2 := mod(new(big.Int).Mul(q.x, z1z1))
	s1 := mod(new(big.Int).Mul(new(big.Int).Mul(p.y, q.z), z2z2))
	s2 := mod(new(big.Int).Mul(new(big.Int).Mul(q.y, p.z), z1z1))
	if u1.Cmp(u2) == 0 {
		if s1.Cmp(s2) == 0 {
			return double(p)
		}
		return inf()
	}
	h := mod(new(big.Int).Sub(u2, u1))
	r := mod(new(big.Int).Sub(s2, s1))
	h2 := mod(new(big.Int).Mul(h, h))
	h3 := mod(new(big.Int).Mul(h2, h))
	v := mod(new(big.Int).Mul(u1, h2))
	x := new(big.Int).Mul(r, r)
	x.Sub(x, h3)
	x.Sub(x, new(big.Int).Lsh(v, 1))
	mod(x)
	y := new(big.Int).Sub(v, x)
	y.Mul(y, r)
	y.Sub(y, new(big.Int).Mul(s1, h3))
	mod(y)
	z := mod(new(big.Int).Mul(new(big.Int).Mul(p.z, q.z), h))
	return point{x, y, z}
}

func mul(p point, k *big.Int) point {
	r := inf()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = double(r)
		if k.Bit(i) == 1 {
			r = add(r, p)
		}
	}
	return r
}

func affine(p point) (x, y *big.Int) {
	zi := new(big.Int).ModInverse(p.z, P)
	zi2 := mod(new(big.Int).Mul(zi, zi))
	x = mod(new(big.Int).Mul(p.x, zi2))
	y = mod(new(big.Int).Mul(new(big.Int).Mul(p.y, zi2), zi))
	return
}

var g = point{Gx, Gy, big.NewInt(1)}

// PublicKey returns the uncompressed public key (X||Y, 64 bytes) of a 32-byte private key.
func PublicKey(priv []byte) ([]byte, error) {
	d := new(big.Int).SetBytes(priv)
	if len(priv) != 32 || d.Sign() == 0 || d.Cmp(N) >= 0 {
		return nil, errors.New("invalid secp256k1 private key")
	}
	x, y := affine(mul(g, d))
	out := make([]byte, 64)
	x.FillBytes(out[:32])
	y.FillBytes(out[32:])
	return out, nil
}

// rfc6979 produces the deterministic nonce candidates for (priv, hash), SHA-256 HMAC-DRBG.
func nonces(priv, hash []byte, try func(k *big.Int) bool) {
	h1 := new(big.Int).SetBytes(hash)
	h1.Mod(h1, N)
	hb := make([]byte, 32)
	h1.FillBytes(hb)
	v := make([]byte, 32)
	k := make([]byte, 32)
	for i := range v {
		v[i] = 1
	}
	mac := func(key []byte, parts ...[]byte) []byte {
		m := hmac.New(sha256.New, key)
		for _, p := range parts {
			m.Write(p)
		}
		return m.Sum(nil)
	}
	k = mac(k, v, []byte{0}, priv, hb)
	v = mac(k, v)
	k = mac(k, v, []byte{1}, priv, hb)
	v = mac(k, v)
	for {
		v = mac(k, v)
		c := new(big.Int).SetBytes(v)
		if c.Sign() > 0 && c.Cmp(N) < 0 && try(c) {
			return
		}
		k = mac(k, v, []byte{0})
		v = mac(k, v)
	}
}

// Sign signs a 32-byte hash and returns r||s||recid (65 bytes, recid 0 or 1, low-s).
func Sign(priv, hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, errors.New("hash must be 32 bytes")
	}
	d := new(big.Int).SetBytes(priv)
	if len(priv) != 32 || d.Sign() == 0 || d.Cmp(N) >= 0 {
		return nil, errors.New("invalid secp256k1 private key")
	}
	e := new(big.Int).SetBytes(hash)
	var out []byte
	nonces(priv, hash, func(k *big.Int) bool {
		rx, ry := affine(mul(g, k))
		r := new(big.Int).Mod(rx, N)
		if r.Sign() == 0 {
			return false
		}
		s := new(big.Int).Mul(r, d)
		s.Add(s, e)
		s.Mul(s, new(big.Int).ModInverse(k, N))
		s.Mod(s, N)
		if s.Sign() == 0 {
			return false
		}
		rec := byte(ry.Bit(0))
		if rx.Cmp(N) >= 0 {
			rec |= 2
		}
		if s.Cmp(halfN) > 0 {
			s.Sub(N, s)
			rec ^= 1
		}
		out = make([]byte, 65)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:64])
		out[64] = rec
		return true
	})
	return out, nil
}

// Recover returns the uncompressed public key (64 bytes) that signed hash, from r||s||recid.
func Recover(hash, sig []byte) ([]byte, error) {
	if len(hash) != 32 || len(sig) != 65 || sig[64] > 3 {
		return nil, errors.New("bad signature")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 || r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return nil, errors.New("bad signature")
	}
	x := new(big.Int).Set(r)
	if sig[64]&2 != 0 {
		x.Add(x, N)
	}
	if x.Cmp(P) >= 0 {
		return nil, errors.New("bad signature")
	}
	y2 := mod(new(big.Int).Mul(x, x))
	y2.Mul(y2, x)
	y2.Add(y2, b7)
	mod(y2)
	y := new(big.Int).ModSqrt(y2, P)
	if y == nil {
		return nil, errors.New("bad signature")
	}
	if byte(y.Bit(0)) != sig[64]&1 {
		y.Sub(P, y)
	}
	rinv := new(big.Int).ModInverse(r, N)
	e := new(big.Int).SetBytes(hash)
	u1 := new(big.Int).Mul(new(big.Int).Sub(N, new(big.Int).Mod(e, N)), rinv)
	u1.Mod(u1, N)
	u2 := new(big.Int).Mul(s, rinv)
	u2.Mod(u2, N)
	q := add(mul(g, u1), mul(point{x, y, big.NewInt(1)}, u2))
	if q.isInf() {
		return nil, errors.New("bad signature")
	}
	qx, qy := affine(q)
	out := make([]byte, 64)
	qx.FillBytes(out[:32])
	qy.FillBytes(out[32:])
	return out, nil
}
