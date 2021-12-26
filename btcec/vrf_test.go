package btcec

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

// GenerateKey generates a fresh keypair for this VRF
func GenerateKey() (*PrivateKey, *PublicKey) {
	sk, err := NewPrivateKey(curve)
	if err != nil {
		return nil, nil
	}
	pk := sk.PubKey()

	return sk, pk
}

func TestH1(t *testing.T) {
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x, y := H1(m)
		if x == nil {
			t.Errorf("H1(%v)=%v, want curve point", m, x)
		}
		if got := curve.IsOnCurve(x, y); !got {
			t.Errorf("H1(%v)=[%v, %v], is not on curve", m, x, y)
		}
	}
}

func TestH2(t *testing.T) {
	l := 32
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x := H2(m)
		if got := len(x.Bytes()); got < 1 || got > l {
			t.Errorf("len(h2(%v)) = %v, want: 1 <= %v <= %v", m, got, got, l)
		}
	}
}

func TestVRF(t *testing.T) {
	sk, pk := GenerateKey()

	m1 := []byte("data1")
	m2 := []byte("data2")
	m3 := []byte("data2")
	output1, proof1 := sk.VRFEval(m1)
	output2, proof2 := sk.VRFEval(m2)
	output3, proof3 := sk.VRFEval(m3)
	for _, tc := range []struct {
		m      []byte
		output [32]byte
		proof  []byte
		err    error
	}{
		{m1, output1, proof1, nil},
		{m2, output2, proof2, nil},
		{m3, output3, proof3, nil},
		{m3, output3, proof2, nil},
		{m3, output3, proof1, ErrInvalidVRF},
	} {
		output, err := pk.VRFVerify(tc.m, tc.proof)
		if got, want := err, tc.err; got != want {
			t.Errorf("VRFVerify(%s, %x): %v, want %v", tc.m, tc.proof, got, want)
		}
		if err != nil {
			continue
		}
		if got, want := output, tc.output; got != want {
			t.Errorf("ProofToInex(%s, %x): %x, want %x", tc.m, tc.proof, got, want)
		}
	}
}

func TestRightTruncateProof(t *testing.T) {
	sk, pk := GenerateKey()

	data := []byte("data")
	_, proof := sk.VRFEval(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[:len(proof)-1]
		if _, err := pk.VRFVerify(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of proof", i)
		}
	}
}

func TestLeftTruncateProof(t *testing.T) {
	sk, pk := GenerateKey()

	data := []byte("data")
	_, proof := sk.VRFEval(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[1:]
		if _, err := pk.VRFVerify(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of proof", i)
		}
	}
}

func TestBitFlip(t *testing.T) {
	sk, pk := GenerateKey()

	data := []byte("data")
	_, proof := sk.VRFEval(data)
	for i := 0; i < len(proof)*8; i++ {
		// Flip bit in position i.
		if _, err := pk.VRFVerify(data, flipBit(proof, i)); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of vrf", i)
		}
	}
}

func flipBit(a []byte, pos int) []byte {
	output := int(math.Floor(float64(pos) / 8))
	b := a[output]
	b ^= (1 << uint(math.Mod(float64(pos), 8.0)))

	var buf bytes.Buffer
	buf.Write(a[:output])
	buf.Write([]byte{b})
	buf.Write(a[output+1:])
	return buf.Bytes()
}
