package derive

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// DefaultDKIMSelector is the DKIM selector used by meltify-dkim when --selector is omitted.
const DefaultDKIMSelector = "mail"

// DKIMKeys holds an unencrypted PKCS#8 DKIM private key and its DNS TXT record.
type DKIMKeys struct {
	// PrivateKeyPEM is an unencrypted PKCS#8 PEM block ("BEGIN PRIVATE KEY").
	// DKIM private keys are stored without a passphrase and protected by file mode.
	PrivateKeyPEM []byte

	// DNSTXTRecord is the TXT value for <selector>._domainkey.<domain>.
	DNSTXTRecord string

	// PublicKeyBase64 is the PKIX SubjectPublicKeyInfo, base64-encoded, without the v=DKIM1 wrapper.
	PublicKeyBase64 string
}

// DKIM derives a DKIM RSA keypair from an Ed25519 private key.
//
// This matches seedify.DeriveDKIMKeypair. The selector is mixed into the
// domain-separation label "seedify:dkim:<selector>:" so different selectors
// produce different RSA keys from the same source key. The private key is
// unencrypted PKCS#8 PEM. bits must be 2048, 3072, or 4096.
func DKIM(key *ed25519.PrivateKey, selector string, bits int) (*DKIMKeys, error) {
	if key == nil {
		return nil, errors.New("ed25519 key is required")
	}
	if selector == "" {
		return nil, errors.New("DKIM selector is required")
	}
	if err := ValidRSABits(bits); err != nil {
		return nil, err
	}

	label := []byte("seedify:dkim:" + selector + ":")
	input := make([]byte, len(label)+len(key.Seed()))
	copy(input, label)
	copy(input[len(label):], key.Seed())

	rsaKey, err := deriveRSAKeyFromDomainHash(sha256.Sum256(input), bits)
	if err != nil {
		return nil, fmt.Errorf("could not derive RSA key for DKIM: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal DKIM private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})

	pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("could not marshal DKIM public key: %w", err)
	}
	pubBase64 := base64.StdEncoding.EncodeToString(pubDER)

	return &DKIMKeys{
		PrivateKeyPEM:   privPEM,
		DNSTXTRecord:    fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubBase64),
		PublicKeyBase64: pubBase64,
	}, nil
}
