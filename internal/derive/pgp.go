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

// derivationEpoch is the fixed creation timestamp stamped on every derived
// artifact that carries one: OpenPGP key packets, DNSSEC .private files, and JKS
// certificates/keystores. A fixed value keeps the derived identity stable — the
// same source Ed25519 key always produces the same OpenPGP fingerprint, DNSSEC
// records, and JKS certificate, regardless of when the command is run.
//
// The timestamp is part of the OpenPGP fingerprint and of the JKS certificate,
// so a live clock would change those identities on every run. GPG also rejects
// keys with creation times in the future, which rules out hash-derived values.
//
// This matches seedify's pgpEpoch (2020-01-01 00:00:00 UTC).
var derivationEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

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

	// CreationTime is the fixed derivation epoch stamped on the OpenPGP key
	// packets. It is part of the OpenPGP fingerprint.
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
	return PGPAt(key, bits, derivationEpoch)
}

// PGPAt is PGP with an explicit creation timestamp stamped on the OpenPGP key
// packets. The timestamp is part of the OpenPGP fingerprint, so callers that
// need a different (or pinned) fingerprint pass it here.
func PGPAt(key *ed25519.PrivateKey, bits int, created time.Time) (*PGPKeys, error) {
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
		CreationTime:  created,
	}, nil
}
