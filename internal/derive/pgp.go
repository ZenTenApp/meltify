package derive

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"
)

// ValidPGPBits reports whether bits is an accepted OpenPGP RSA size.
func ValidPGPBits(bits int) error {
	return ValidRSABits(bits)
}

// DefaultPGPBits is the OpenPGP RSA size used by meltify-pgp when --bits is omitted.
const DefaultPGPBits = DefaultRSABits

// pgpEpoch is the fixed creation timestamp stamped on all OpenPGP keys
// derived by meltify. Using a well-known past date instead of a live
// clock or a hash-derived value guarantees two properties simultaneously:
//  1. Determinism: the same source Ed25519 key always produces the same
//     OpenPGP fingerprint, regardless of when the command is run.
//  2. GPG compatibility: GPG rejects keys with creation times in the future,
//     so using a hash-derived timestamp risks rejection for some source keys.
//
// This matches seedify's pgpEpoch (2020-01-01 00:00:00 UTC).
var pgpEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// PGPKeys holds the two RSA keys needed to build a standard OpenPGP secret
// key block: a primary key used for signing and certification ([SC]), and an
// encryption subkey ([E]). Both are derived deterministically from the same
// Ed25519 source key using distinct domain-separation labels.
type PGPKeys struct {
	// PrimaryKey is the RSA private key for the OpenPGP primary key packet.
	// It carries the [SC] (Sign + Certify) usage flags.
	PrimaryKey *rsa.PrivateKey

	// EncryptSubkey is the RSA private key for the OpenPGP encryption subkey
	// packet. It carries the [E] (Encrypt) usage flag.
	EncryptSubkey *rsa.PrivateKey

	// CreationTime is the fixed PGP epoch (2020-01-01 00:00:00 UTC).
	CreationTime time.Time
}

// PGP derives a pair of RSA private keys from an Ed25519 private key,
// intended for use as an OpenPGP primary key (signing / certification) and
// encryption subkey.
//
// The two keys are derived with separate domain-separation labels matching
// seedify.DerivePGPKeypair:
//   - Primary key: "seedify:pgp:primary:" + seed
//   - Encryption subkey: "seedify:pgp:encrypt:" + seed
//
// bits must be 2048, 3072, or 4096. 4096 is strongly recommended.
// This function is computationally expensive because it involves prime search.
func PGP(key *ed25519.PrivateKey, bits int) (*PGPKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}
	if err := ValidPGPBits(bits); err != nil {
		return nil, err
	}

	primaryLabel := []byte("seedify:pgp:primary:")
	primaryInput := make([]byte, len(primaryLabel)+len(key.Seed()))
	copy(primaryInput, primaryLabel)
	copy(primaryInput[len(primaryLabel):], key.Seed())
	primaryHash := sha256.Sum256(primaryInput)

	primaryKey, err := deriveRSAKeyFromDomainHash(primaryHash, bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive PGP primary key: %w", err)
	}

	encryptLabel := []byte("seedify:pgp:encrypt:")
	encryptInput := make([]byte, len(encryptLabel)+len(key.Seed()))
	copy(encryptInput, encryptLabel)
	copy(encryptInput[len(encryptLabel):], key.Seed())

	encryptKey, err := deriveRSAKeyFromDomainHash(sha256.Sum256(encryptInput), bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive PGP encryption subkey: %w", err)
	}

	return &PGPKeys{
		PrimaryKey:    primaryKey,
		EncryptSubkey: encryptKey,
		CreationTime:  pgpEpoch,
	}, nil
}
