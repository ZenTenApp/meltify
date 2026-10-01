package derive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// DefaultRSABits is the RSA size used by meltify-rsa when --bits is omitted.
const DefaultRSABits = 4096

// validRSABits is the set of accepted RSA key sizes for RSA and PGP derivation.
var validRSABits = map[int]struct{}{
	2048: {},
	3072: {},
	4096: {},
}

// ValidRSABits reports whether bits is an accepted RSA size.
func ValidRSABits(bits int) error {
	if _, ok := validRSABits[bits]; !ok {
		return fmt.Errorf("invalid RSA bit size %d: must be 2048, 3072, or 4096", bits)
	}
	return nil
}

// RSA deterministically derives an RSA private key from an Ed25519 private key.
//
// This matches seedify.DeriveRSAKeyFromEd25519: the Ed25519 seed is
// domain-separated with the label "seedify:rsa-from-ed25519:", hashed with
// SHA-256, and used as the AES-256-CTR seed for prime generation.
//
// bits must be 2048, 3072, or 4096. 4096 is strongly recommended.
// This function is computationally expensive because it involves prime search.
func RSA(key *ed25519.PrivateKey, bits int) (*rsa.PrivateKey, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}
	if err := ValidRSABits(bits); err != nil {
		return nil, err
	}

	label := []byte("seedify:rsa-from-ed25519:")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())

	return deriveRSAKeyFromDomainHash(sha256.Sum256(input), bits)
}

// rsaPublicExponent is the standard RSA public exponent (2^16 + 1 = 65537).
const rsaPublicExponent = 65537

// deterministicPrime generates a prime of exactly the given bit length using
// only the provided io.Reader for randomness. It sets the two highest bits to
// guarantee that two such primes multiplied together produce a product of
// exactly 2×bits bits, and sets the lowest bit to ensure the candidate is odd.
//
// Primality is tested with big.Int.ProbablyPrime(0), which applies the
// deterministic Baillie-PSW test and has no known false positives. This avoids
// the non-determinism introduced by big.Int.ProbablyPrime(n>0), which draws
// random Miller-Rabin witnesses from crypto/rand.Reader regardless of the
// caller-provided reader.
func deterministicPrime(prng io.Reader, bits int) (*big.Int, error) {
	if bits < 2 { //nolint:mnd
		return nil, fmt.Errorf("prime size must be at least 2 bits, got %d", bits)
	}

	b := make([]byte, (bits+7)/8) //nolint:mnd
	for {
		if _, err := io.ReadFull(prng, b); err != nil {
			return nil, fmt.Errorf("could not read random bytes: %w", err)
		}

		p := new(big.Int).SetBytes(b)

		// Mask to exactly `bits` bits.
		mask := new(big.Int).Lsh(big.NewInt(1), uint(bits))
		mask.Sub(mask, big.NewInt(1))
		p.And(p, mask)

		// Set the two highest bits so that the product of two such primes has
		// exactly 2×bits bits — identical to the guarantee from crypto/rand.Prime.
		p.SetBit(p, bits-1, 1)
		p.SetBit(p, bits-2, 1) //nolint:mnd

		// Ensure the candidate is odd.
		p.SetBit(p, 0, 1)

		if p.BitLen() == bits && p.ProbablyPrime(0) {
			return p, nil
		}
	}
}

// deterministicReader is an io.Reader backed by an AES-256-CTR stream cipher.
// It produces an infinite, reproducible byte stream from a fixed 32-byte seed,
// making it suitable for deterministic cryptographic key generation.
type deterministicReader struct {
	stream cipher.Stream
}

// Read fills p with deterministic pseudo-random bytes from the AES-CTR stream.
func (r *deterministicReader) Read(p []byte) (int, error) {
	// XOR a zero buffer with the stream to produce the keystream bytes.
	for i := range p {
		p[i] = 0
	}
	r.stream.XORKeyStream(p, p)
	return len(p), nil
}

// newDeterministicReader constructs a deterministicReader using the given
// 32-byte seed as an AES-256 key. The IV is all-zero; the seed must be
// domain-separated by the caller before passing it in.
func newDeterministicReader(seed []byte) (io.Reader, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %w", err)
	}
	var iv [aes.BlockSize]byte
	stream := cipher.NewCTR(block, iv[:])
	return &deterministicReader{stream: stream}, nil
}

// deriveRSAKeyFromDomainHash generates an RSA private key of the given bit
// size from a pre-computed 32-byte domain hash. The hash is used as the
// AES-256 seed for a deterministic CTR-mode PRNG that drives prime generation.
//
// Callers are responsible for constructing a properly domain-separated hash
// before passing it in; this function treats the bytes as opaque key material.
// bits must be 2048, 3072, or 4096.
func deriveRSAKeyFromDomainHash(domainHash [32]byte, bits int) (*rsa.PrivateKey, error) {
	if _, ok := validRSABits[bits]; !ok {
		return nil, fmt.Errorf("invalid RSA bit size %d: must be 2048, 3072, or 4096", bits)
	}

	prng, err := newDeterministicReader(domainHash[:])
	if err != nil {
		return nil, fmt.Errorf("could not create deterministic reader: %w", err)
	}

	// Generate P and Q as distinct primes from the deterministic stream.
	// deterministicPrime uses ProbablyPrime(0) (Baillie-PSW) which is fully
	// deterministic — unlike crypto/rand.Prime which calls ProbablyPrime(20)
	// and draws random Miller-Rabin witnesses from crypto/rand.Reader.
	halfBits := bits / 2 //nolint:mnd
	p, err := deterministicPrime(prng, halfBits)
	if err != nil {
		return nil, fmt.Errorf("could not generate prime P: %w", err)
	}

	var q *big.Int
	for {
		q, err = deterministicPrime(prng, halfBits)
		if err != nil {
			return nil, fmt.Errorf("could not generate prime Q: %w", err)
		}
		if p.Cmp(q) != 0 {
			break
		}
	}

	// Compute the RSA key components.
	one := big.NewInt(1)
	n := new(big.Int).Mul(p, q)
	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)
	phi := new(big.Int).Mul(pm1, qm1)

	e := big.NewInt(rsaPublicExponent)
	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		return nil, fmt.Errorf("could not compute RSA private exponent: gcd(e, phi) != 1")
	}

	rsaKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: n,
			E: rsaPublicExponent,
		},
		D:      d,
		Primes: []*big.Int{p, q},
	}
	rsaKey.Precompute()

	if err := rsaKey.Validate(); err != nil {
		return nil, fmt.Errorf("derived RSA key failed validation: %w", err)
	}

	return rsaKey, nil
}
