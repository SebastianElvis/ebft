package btcec

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
)

// Discrete Log based VRF from Appendix A of CONIKS:
// http://www.jbonneau.com/doc/MBBFF15-coniks.pdf
// based on "Unique Ring Signatures, a Practical Construction"
// http://fc13.ifca.ai/proc/5-1.pdf

var (
	curve = S256()
	// ErrInvalidVRF err
	ErrInvalidVRF = errors.New("invalid VRF proof")
)

// Unmarshal a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return // unrecognized point encoding
	}
	if len(data) != 1+byteLen {
		return
	}

	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	params := curve.Params()
	tx := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y2 := y2(params, tx)
	sqrt := defaultSqrt
	ty := sqrt(y2, params.P)
	if ty == nil {
		return // "y^2" is not a square: invalid point
	}
	var y2c big.Int
	y2c.Mul(ty, ty).Mod(&y2c, params.P)
	if y2c.Cmp(y2) != 0 {
		return // sqrt(y2)^2 != y2: invalid point
	}
	if ty.Bit(0) != uint(data[0]&1) {
		ty.Sub(params.P, ty)
	}

	x, y = tx, ty // valid point: return it
	return
}

// Use the curve equation to calculate y² given x.
// only applies to curves of the form y² = x³ + b.
func y2(curve *elliptic.CurveParams, x *big.Int) *big.Int {

	// y² = x³ + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	//threeX := new(big.Int).Lsh(x, 1)
	//threeX.Add(threeX, x)
	//
	//x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	return x3
}

func defaultSqrt(x, p *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(x, p) {
		return nil // x is not a square
	}
	return &r
}

/// H1 hashes m to a curve point
func H1(m []byte) (x, y *big.Int) {
	h := sha512.New()
	var i uint32
	byteLen := (curve.BitSize + 7) >> 3
	for x == nil && i < 100 {
		// TODO: Use a NIST specified DRBG.
		h.Reset()
		if err := binary.Write(h, binary.BigEndian, i); err != nil {
			panic(err)
		}
		if _, err := h.Write(m); err != nil {
			panic(err)
		}
		r := []byte{2} // Set point encoding to "compressed", y=0.
		r = h.Sum(r)
		x, y = Unmarshal(curve, r[:byteLen+1])
		i++
	}
	return
}

// H2 hashes to an integer [1,N-1]
func H2(m []byte) *big.Int {
	// NIST SP 800-90A § A.5.1: Simple discard method.
	byteLen := (curve.BitSize + 7) >> 3
	h := sha512.New()
	for i := uint32(0); ; i++ {
		// TODO: Use a NIST specified DRBG.
		h.Reset()
		if err := binary.Write(h, binary.BigEndian, i); err != nil {
			panic(err)
		}
		if _, err := h.Write(m); err != nil {
			panic(err)
		}
		b := h.Sum(nil)
		sk := new(big.Int).SetBytes(b[:byteLen])
		if sk.Cmp(new(big.Int).Sub(curve.N, one)) == -1 {
			return sk.Add(sk, one)
		}
	}
}

// VRFEval returns the verifiable unpredictable function evaluated at m
func (sk *PrivateKey) VRFEval(m []byte) (output [32]byte, proof []byte) {
	nilOutput := [32]byte{}
	// Prover chooses r <-- [1,N-1]
	r, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nilOutput, nil
	}
	ri := new(big.Int).SetBytes(r)

	// H = H1(m)
	Hx, Hy := H1(m)

	// VRF_sk(m) = [sk]H
	sHx, sHy := curve.ScalarMult(Hx, Hy, sk.D.Bytes())
	vrf := elliptic.Marshal(curve, sHx, sHy) // 65 bytes.

	// G is the base point
	// s = H2(G, H, [sk]G, VRF, [r]G, [r]H)
	rGx, rGy := curve.ScalarBaseMult(r)
	rHx, rHy := curve.ScalarMult(Hx, Hy, r)
	var b bytes.Buffer
	if _, err := b.Write(elliptic.Marshal(curve, curve.Gx, curve.Gy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, Hx, Hy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, sk.PublicKey.X, sk.PublicKey.Y)); err != nil {
		panic(err)
	}
	if _, err := b.Write(vrf); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, rGx, rGy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, rHx, rHy)); err != nil {
		panic(err)
	}
	s := H2(b.Bytes())

	// t = r−s*sk mod N
	t := new(big.Int).Sub(ri, new(big.Int).Mul(s, sk.D))
	t.Mod(t, curve.N)

	// output = H(vrf)
	output = sha256.Sum256(vrf)

	// Write s, t, and vrf to a proof blob. Also write leading zeros before s and t
	// if needed.
	var buf bytes.Buffer
	if _, err := buf.Write(make([]byte, 32-len(s.Bytes()))); err != nil {
		panic(err)
	}
	if _, err := buf.Write(s.Bytes()); err != nil {
		panic(err)
	}
	if _, err := buf.Write(make([]byte, 32-len(t.Bytes()))); err != nil {
		panic(err)
	}
	if _, err := buf.Write(t.Bytes()); err != nil {
		panic(err)
	}
	if _, err := buf.Write(vrf); err != nil {
		panic(err)
	}

	return output, buf.Bytes()
}

// VRFVerify asserts that proof is correct for m and outputs output.
func (pk *PublicKey) VRFVerify(m, proof []byte) (output [32]byte, err error) {
	nilOutput := [32]byte{}
	// verifier checks that s == H2(m, [t]G + [s]([sk]G), [t]H1(m) + [s]VRF_k(m))
	if got, want := len(proof), 64+65; got != want {
		return nilOutput, ErrInvalidVRF
	}

	// Parse proof into s, t, and vrf.
	s := proof[0:32]
	t := proof[32:64]
	vrf := proof[64 : 64+65]

	uHx, uHy := elliptic.Unmarshal(curve, vrf)
	if uHx == nil {
		return nilOutput, ErrInvalidVRF
	}

	// [t]G + [s]([sk]G) = [t+k*sk]G
	tGx, tGy := curve.ScalarBaseMult(t)
	ksGx, ksGy := curve.ScalarMult(pk.X, pk.Y, s)
	tksGx, tksGy := curve.Add(tGx, tGy, ksGx, ksGy)

	// H = H1(m)
	// [t]H + [s]VRF = [t+k*sk]H
	Hx, Hy := H1(m)
	tHx, tHy := curve.ScalarMult(Hx, Hy, t)
	sHx, sHy := curve.ScalarMult(uHx, uHy, s)
	tksHx, tksHy := curve.Add(tHx, tHy, sHx, sHy)

	//   H2(G, H, [sk]G, VRF, [t]G + [s]([sk]G), [t]H + [s]VRF)
	// = H2(G, H, [sk]G, VRF, [t+k*sk]G, [t+k*sk]H)
	// = H2(G, H, [sk]G, VRF, [r]G, [r]H)
	var b bytes.Buffer
	if _, err := b.Write(elliptic.Marshal(curve, curve.Gx, curve.Gy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, Hx, Hy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, pk.X, pk.Y)); err != nil {
		panic(err)
	}
	if _, err := b.Write(vrf); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, tksGx, tksGy)); err != nil {
		panic(err)
	}
	if _, err := b.Write(elliptic.Marshal(curve, tksHx, tksHy)); err != nil {
		panic(err)
	}
	h2 := H2(b.Bytes())

	// Left pad h2 with zeros if needed. This will ensure that h2 is padded
	// the same way s is.
	var buf bytes.Buffer
	if _, err := buf.Write(make([]byte, 32-len(h2.Bytes()))); err != nil {
		panic(err)
	}
	if _, err := buf.Write(h2.Bytes()); err != nil {
		panic(err)
	}

	if !hmac.Equal(s, buf.Bytes()) {
		return nilOutput, ErrInvalidVRF
	}
	return sha256.Sum256(vrf), nil
}
